#define _POSIX_C_SOURCE 200809L

#include "weed.h"
#include "weed_format.h"
#include "le.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xxhash.h>

#define WEED_BUFFER_SIZE    (64*1024)

/*
 * Streaming packer:
 *  - Phase A: collect path inventory only (disk + archive path strings).
 *  - Phase B: open .weed, stream each FILEITEM immediately (identity + twins),
 *    keep only catalog metadata (hash/offset/path/encoding) in RAM.
 *  - Phase C: sort catalog, append little-endian header at EOF, sign.
 *
 * Peak memory ≈ one file (if --compress) + O(N) path strings + O(N) catalog.
 */

/* Lightweight inventory before streaming. */
struct file_job {
	char *disk_path;
	char *arch_path;
	size_t arch_path_len;
	int is_root;
};

struct job_list {
	struct file_job *v;
	size_t n;
	size_t cap;
};

/* LE-header catalog only — no file bodies. */
struct cat_entry {
	char *arch_path;
	size_t arch_path_len;
	uint8_t encoding;
	uint64_t hash;
	uint64_t offset;
};

struct catalog {
	struct cat_entry *v;
	size_t n;
	size_t cap;
};

struct pack_ctx {
	FILE *out;
	struct catalog cat;
	const char *root_file;
	unsigned compress_flags;
	size_t n_id;
	size_t n_br;
	size_t n_gz;
};

static int jobs_push(struct job_list *l, struct file_job j)
{
	if (l->n == l->cap) {
		size_t ncap = l->cap ? l->cap * 2 : 64;
		struct file_job *nv =
		    (struct file_job *)realloc(l->v, ncap * sizeof(*nv));
		if (!nv)
			return -1;
		l->v = nv;
		l->cap = ncap;
	}
	l->v[l->n++] = j;
	return 0;
}

static void jobs_free(struct job_list *l)
{
	for (size_t i = 0; i < l->n; i++) {
		free(l->v[i].disk_path);
		free(l->v[i].arch_path);
	}
	free(l->v);
	memset(l, 0, sizeof *l);
}

static int cat_push(struct catalog *c, struct cat_entry e)
{
	if (c->n == c->cap) {
		size_t ncap = c->cap ? c->cap * 2 : 64;
		struct cat_entry *nv =
		    (struct cat_entry *)realloc(c->v, ncap * sizeof(*nv));
		if (!nv)
			return -1;
		c->v = nv;
		c->cap = ncap;
	}
	c->v[c->n++] = e;
	return 0;
}

static void cat_free(struct catalog *c)
{
	for (size_t i = 0; i < c->n; i++)
		free(c->v[i].arch_path);
	free(c->v);
	memset(c, 0, sizeof *c);
}

static int cmp_cat(const void *a, const void *b)
{
	const struct cat_entry *ea = *(const struct cat_entry *const *)a;
	const struct cat_entry *eb = *(const struct cat_entry *const *)b;
	if (ea->hash < eb->hash)
		return -1;
	if (ea->hash > eb->hash)
		return 1;
	size_t n = ea->arch_path_len < eb->arch_path_len ? ea->arch_path_len
	                                                 : eb->arch_path_len;
	int c = memcmp(ea->arch_path, eb->arch_path, n);
	if (c != 0)
		return c;
	if (ea->arch_path_len < eb->arch_path_len)
		return -1;
	if (ea->arch_path_len > eb->arch_path_len)
		return 1;
	if (ea->encoding < eb->encoding)
		return -1;
	if (ea->encoding > eb->encoding)
		return 1;
	return 0;
}

static int path_join(const char *a, const char *b, char **out)
{
	size_t la = strlen(a);
	size_t lb = strlen(b);
	int need_slash = (la > 0 && a[la - 1] != '/');
	size_t n = la + lb + (need_slash ? 1 : 0) + 1;
	char *p = (char *)malloc(n);
	if (!p)
		return -1;
	memcpy(p, a, la);
	size_t o = la;
	if (need_slash)
		p[o++] = '/';
	memcpy(p + o, b, lb);
	p[o + lb] = '\0';
	*out = p;
	return 0;
}

static int clean_list_path(char *line, size_t *len_out)
{
	size_t n = strlen(line);
	while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
	while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t'))
		line[--n] = '\0';

	char *p = line;
	while (*p == ' ' || *p == '\t')
		p++;
	if (p != line)
		memmove(line, p, strlen(p) + 1);

	n = strlen(line);
	if (n == 0)
		return 1;

	while (n >= 2 && line[0] == '.' && line[1] == '/') {
		memmove(line, line + 2, n - 1);
		n -= 2;
	}
	while (n > 0 && line[0] == '/') {
		memmove(line, line + 1, n);
		n--;
	}
	if (n == 0)
		return 1;

	for (size_t i = 0; i < n; i++) {
		if (line[i] == '.' && i + 1 < n && line[i + 1] == '.' &&
		    (i + 2 == n || line[i + 2] == '/') &&
		    (i == 0 || line[i - 1] == '/')) {
			fprintf(stderr, "weed: refusing path with '..': %s\n", line);
			return -1;
		}
	}
	*len_out = n;
	return 0;
}

static void store_xxh128(XXH128_hash_t h, uint8_t out[WEED_ETAG_SIZE])
{
	uint64_t lo = h.low64;
	uint64_t hi = h.high64;
	for (int i = 0; i < 8; i++) {
		out[i] = (uint8_t)(lo >> (8 * i));
		out[8 + i] = (uint8_t)(hi >> (8 * i));
	}
}

/* Stream file once: compute ETag without holding the whole body. */
static int etag_file_stream(const char *path, uint64_t expect_len,
                            uint8_t etag[WEED_ETAG_SIZE])
{
	FILE *f = fopen(path, "rb");
	if (!f) {
		perror(path);
		return -1;
	}
	XXH3_state_t *st = XXH3_createState();
	if (!st || XXH3_128bits_reset_withSeed(st, WEED_ETAG_SEED) == XXH_ERROR) {
		fprintf(stderr, "weed: xxhash state failed\n");
		if (st)
			XXH3_freeState(st);
		fclose(f);
		return -1;
	}
	unsigned char buf[WEED_BUFFER_SIZE];
	uint64_t total = 0;
	for (;;) {
		size_t n = fread(buf, 1, sizeof buf, f);
		if (n > 0) {
			XXH3_128bits_update(st, buf, n);
			total += n;
		}
		if (n < sizeof buf) {
			if (ferror(f)) {
				perror(path);
				XXH3_freeState(st);
				fclose(f);
				return -1;
			}
			break;
		}
	}
	fclose(f);
	if (total != expect_len) {
		fprintf(stderr, "weed: size changed while hashing: %s\n", path);
		XXH3_freeState(st);
		return -1;
	}
	store_xxh128(XXH3_128bits_digest(st), etag);
	XXH3_freeState(st);
	return 0;
}

static int copy_file_stream(FILE *out, const char *path, uint64_t expect_len)
{
	FILE *in = fopen(path, "rb");
	if (!in) {
		perror(path);
		return -1;
	}
	unsigned char buf[WEED_BUFFER_SIZE];
	uint64_t total = 0;
	for (;;) {
		size_t n = fread(buf, 1, sizeof buf, in);
		if (n > 0) {
			if (fwrite(buf, 1, n, out) != n) {
				perror("fwrite content");
				fclose(in);
				return -1;
			}
			total += n;
		}
		if (n < sizeof buf) {
			if (ferror(in)) {
				perror(path);
				fclose(in);
				return -1;
			}
			break;
		}
	}
	fclose(in);
	if (total != expect_len) {
		fprintf(stderr, "weed: size changed while packing: %s\n", path);
		return -1;
	}
	return 0;
}

static int read_file_all(const char *path, unsigned char **out, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	if (!f) {
		perror(path);
		return -1;
	}
	if (fseeko(f, 0, SEEK_END) != 0) {
		perror(path);
		fclose(f);
		return -1;
	}
	off_t sz = ftello(f);
	if (sz < 0) {
		fclose(f);
		return -1;
	}
	if (fseeko(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return -1;
	}
	unsigned char *buf = (unsigned char *)malloc((size_t)sz ? (size_t)sz : 1);
	if (!buf) {
		fclose(f);
		return -1;
	}
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		perror(path);
		free(buf);
		fclose(f);
		return -1;
	}
	fclose(f);
	*out = buf;
	*out_len = (size_t)sz;
	return 0;
}

static int cat_has_dup(const struct catalog *c, const char *arch, size_t arch_len,
                       uint8_t encoding)
{
	for (size_t i = 0; i < c->n; i++) {
		if (c->v[i].encoding == encoding && c->v[i].arch_path_len == arch_len &&
		    memcmp(c->v[i].arch_path, arch, arch_len) == 0)
			return 1;
	}
	return 0;
}

/*
 * Write one FILEITEM at current out position; append catalog row.
 * content: if non-NULL write that buffer; else stream from disk_path.
 * Takes no ownership of arch (copies for catalog).
 */
static int emit_fileitem(struct pack_ctx *ctx, const char *arch, size_t arch_len,
                         const char *mime, uint32_t mime_len, uint8_t encoding,
                         uint8_t cache_flags, uint32_t max_age,
                         const uint8_t etag[WEED_ETAG_SIZE], uint64_t content_len,
                         const unsigned char *content, const char *disk_path)
{
	if (arch_len > 0xffffffffu || mime_len > 0xffffffffu) {
		fprintf(stderr, "weed: path or mime too long\n");
		return -1;
	}
	if (cat_has_dup(&ctx->cat, arch, arch_len, encoding)) {
		fprintf(stderr, "weed: duplicate path+encoding \"%.*s\" enc=%u\n",
		        (int)arch_len, arch, encoding);
		return -1;
	}

	off_t pos = ftello(ctx->out);
	if (pos < 0) {
		perror("ftello");
		return -1;
	}

	if (weed_write_u64_le(ctx->out, content_len) != 0 ||
	    weed_write_u32_le(ctx->out, (uint32_t)arch_len) != 0 ||
	    weed_write_u32_le(ctx->out, mime_len) != 0) {
		perror("fwrite fileitem header");
		return -1;
	}
	if (fputc((int)encoding, ctx->out) == EOF ||
	    fputc((int)cache_flags, ctx->out) == EOF) {
		perror("fwrite encoding/cache");
		return -1;
	}
	if (weed_write_u32_le(ctx->out, max_age) != 0) {
		perror("fwrite max_age");
		return -1;
	}
	if (fwrite(etag, 1, WEED_ETAG_SIZE, ctx->out) != WEED_ETAG_SIZE) {
		perror("fwrite etag");
		return -1;
	}
	if (arch_len && fwrite(arch, 1, arch_len, ctx->out) != arch_len) {
		perror("fwrite path");
		return -1;
	}
	if (mime_len && fwrite(mime, 1, mime_len, ctx->out) != mime_len) {
		perror("fwrite mime");
		return -1;
	}

	if (content) {
		if (content_len &&
		    fwrite(content, 1, (size_t)content_len, ctx->out) !=
		        (size_t)content_len) {
			perror("fwrite content");
			return -1;
		}
	} else {
		if (copy_file_stream(ctx->out, disk_path, content_len) != 0)
			return -1;
	}

	char *path_copy = (char *)malloc(arch_len ? arch_len : 1);
	if (!path_copy)
		return -1;
	if (arch_len)
		memcpy(path_copy, arch, arch_len);

	struct cat_entry ce;
	memset(&ce, 0, sizeof ce);
	ce.arch_path = path_copy;
	ce.arch_path_len = arch_len;
	ce.encoding = encoding;
	ce.hash = XXH64(arch, arch_len, WEED_XXH_SEED);
	ce.offset = (uint64_t)pos;
	if (cat_push(&ctx->cat, ce) != 0) {
		free(path_copy);
		return -1;
	}

	if (encoding == WEED_ENC_IDENTITY)
		ctx->n_id++;
	else if (encoding == WEED_ENC_BR)
		ctx->n_br++;
	else if (encoding == WEED_ENC_GZIP)
		ctx->n_gz++;
	return 0;
}

/* Process one source file: stream identity (+ twins) to archive, free temps. */
static int stream_one_file(struct pack_ctx *ctx, const struct file_job *job)
{
	struct stat st;
	if (stat(job->disk_path, &st) != 0) {
		perror(job->disk_path);
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "weed: not a regular file: %s\n", job->disk_path);
		return -1;
	}

	uint64_t raw_len = (uint64_t)st.st_size;
	const char *mime = weed_mime_from_path(job->arch_path, job->arch_path_len);
	if (job->is_root)
		mime = "text/html";
	uint32_t mime_len = (uint32_t)strlen(mime);

	uint8_t cache_flags = WEED_CACHE_NO_CACHE;
	uint32_t max_age = 0;
	weed_cache_for_mime(mime, &cache_flags, &max_age);

	unsigned char *raw = NULL;
	size_t raw_sz = 0;

	if (ctx->compress_flags) {
		/* One-file buffer only when compression is requested. */
		if (read_file_all(job->disk_path, &raw, &raw_sz) != 0)
			return -1;
		if ((uint64_t)raw_sz != raw_len) {
			fprintf(stderr, "weed: size changed: %s\n", job->disk_path);
			free(raw);
			return -1;
		}

		uint8_t etag_id[WEED_ETAG_SIZE];
		weed_etag_xxh128(raw, raw_sz, etag_id);

		if (emit_fileitem(ctx, job->arch_path, job->arch_path_len, mime,
		                  mime_len, WEED_ENC_IDENTITY, cache_flags, max_age,
		                  etag_id, raw_len, raw, NULL) != 0) {
			free(raw);
			return -1;
		}

		if (ctx->compress_flags & WEED_COMPRESS_BR) {
			unsigned char *br = NULL;
			size_t br_len = 0;
			int rc = weed_compress_br(raw, raw_sz, &br, &br_len);
			if (rc < 0) {
				fprintf(stderr, "weed: brotli failed for %s\n",
				        job->disk_path);
				free(raw);
				return -1;
			}
			if (rc == 0) {
				uint8_t etag_br[WEED_ETAG_SIZE];
				weed_etag_xxh128(br, br_len, etag_br);
				if (emit_fileitem(ctx, job->arch_path, job->arch_path_len,
				                  mime, mime_len, WEED_ENC_BR, cache_flags,
				                  max_age, etag_br, br_len, br, NULL) != 0) {
					free(br);
					free(raw);
					return -1;
				}
				free(br); /* written; do not keep */
			}
		}

		if (ctx->compress_flags & WEED_COMPRESS_GZIP) {
			unsigned char *gz = NULL;
			size_t gz_len = 0;
			int rc = weed_compress_gzip(raw, raw_sz, &gz, &gz_len);
			if (rc < 0) {
				fprintf(stderr, "weed: gzip failed for %s\n",
				        job->disk_path);
				free(raw);
				return -1;
			}
			if (rc == 0) {
				uint8_t etag_gz[WEED_ETAG_SIZE];
				weed_etag_xxh128(gz, gz_len, etag_gz);
				if (emit_fileitem(ctx, job->arch_path, job->arch_path_len,
				                  mime, mime_len, WEED_ENC_GZIP, cache_flags,
				                  max_age, etag_gz, gz_len, gz, NULL) != 0) {
					free(gz);
					free(raw);
					return -1;
				}
				free(gz);
			}
		}

		free(raw);
		return 0;
	}

	/* No compress: stream hash + stream copy, never hold full body. */
	uint8_t etag_id[WEED_ETAG_SIZE];
	if (etag_file_stream(job->disk_path, raw_len, etag_id) != 0)
		return -1;
	return emit_fileitem(ctx, job->arch_path, job->arch_path_len, mime, mime_len,
	                     WEED_ENC_IDENTITY, cache_flags, max_age, etag_id,
	                     raw_len, NULL, job->disk_path);
}

static int finish_archive(struct pack_ctx *ctx, const char *out_path,
                          const char *key_path)
{
	uint64_t n = (uint64_t)ctx->cat.n;

	struct cat_entry **idx =
	    (struct cat_entry **)malloc(n ? n * sizeof(*idx) : 1);
	if (!idx)
		return -1;
	for (size_t i = 0; i < ctx->cat.n; i++)
		idx[i] = &ctx->cat.v[i];
	qsort(idx, ctx->cat.n, sizeof(*idx), cmp_cat);

	for (size_t i = 0; i < ctx->cat.n; i++) {
		if (weed_write_u64_le(ctx->out, idx[i]->hash) != 0) {
			perror("fwrite hash");
			free(idx);
			return -1;
		}
	}
	for (size_t i = 0; i < ctx->cat.n; i++) {
		if (weed_write_u64_le(ctx->out, idx[i]->offset) != 0) {
			perror("fwrite offset");
			free(idx);
			return -1;
		}
	}
	free(idx);

	unsigned char reserved[WEED_RESERVED_SIZE];
	memset(reserved, 0, sizeof reserved);
	reserved[0] = (unsigned char)WEED_VERSION;
	if (fwrite(reserved, 1, WEED_RESERVED_SIZE, ctx->out) != WEED_RESERVED_SIZE) {
		perror("fwrite reserved");
		return -1;
	}
	if (weed_write_u64_le(ctx->out, n) != 0) {
		perror("fwrite file_count");
		return -1;
	}
	if (fflush(ctx->out) != 0) {
		perror("fflush");
		return -1;
	}
	fclose(ctx->out);
	ctx->out = NULL;

	if (weed_sign_file(key_path, out_path) != 0)
		return -1;

	fprintf(stderr,
	        "weed: packed %llu item(s) (identity=%zu br=%zu gzip=%zu) -> %s\n",
	        (unsigned long long)n, ctx->n_id, ctx->n_br, ctx->n_gz, out_path);
	return 0;
}

static int ensure_root_file_ok(const char *root_file)
{
	if (!root_file || !root_file[0])
		return 0;
	if (strchr(root_file, '/')) {
		fprintf(stderr,
		        "weed: root file must be a single name (got \"%s\")\n",
		        root_file);
		return -1;
	}
	return 0;
}

static void promote_root_job(struct job_list *jobs)
{
	size_t ri = (size_t)-1;
	for (size_t i = 0; i < jobs->n; i++) {
		if (jobs->v[i].is_root) {
			ri = i;
			break;
		}
	}
	if (ri != (size_t)-1 && ri != 0) {
		struct file_job tmp = jobs->v[0];
		jobs->v[0] = jobs->v[ri];
		jobs->v[ri] = tmp;
	}
}

static int jobs_has_arch(const struct job_list *jobs, const char *arch,
                         size_t arch_len)
{
	for (size_t i = 0; i < jobs->n; i++) {
		if (jobs->v[i].arch_path_len == arch_len &&
		    memcmp(jobs->v[i].arch_path, arch, arch_len) == 0)
			return 1;
	}
	return 0;
}

static int add_job(struct job_list *jobs, const char *disk_path, char *arch,
                   size_t arch_len, const char *root_file, int *have_root)
{
	int is_root = 0;
	if (root_file && strcmp(arch, root_file) == 0) {
		free(arch);
		arch = (char *)malloc(1);
		if (!arch)
			return -1;
		arch[0] = '\0';
		arch_len = 0;
		is_root = 1;
		*have_root = 1;
	}

	if (jobs_has_arch(jobs, arch, arch_len)) {
		fprintf(stderr, "weed: duplicate archive path \"%.*s\"\n",
		        (int)arch_len, arch);
		free(arch);
		return -1;
	}

	struct file_job j;
	memset(&j, 0, sizeof j);
	j.disk_path = strdup(disk_path);
	if (!j.disk_path) {
		free(arch);
		return -1;
	}
	j.arch_path = arch;
	j.arch_path_len = arch_len;
	j.is_root = is_root;
	if (jobs_push(jobs, j) != 0) {
		free(j.disk_path);
		free(j.arch_path);
		return -1;
	}
	return 0;
}

static int collect_file(struct job_list *jobs, const char *disk_path,
                        const char *root_dir, const char *root_file,
                        int *have_root)
{
	struct stat st;
	if (stat(disk_path, &st) != 0) {
		perror(disk_path);
		return -1;
	}
	if (!S_ISREG(st.st_mode))
		return 0;

	char *arch = NULL;
	size_t arch_len = 0;
	if (weed_relpath_nfc(root_dir, disk_path, &arch, &arch_len) != 0)
		return -1;
	return add_job(jobs, disk_path, arch, arch_len, root_file, have_root);
}

static int walk_dir(struct job_list *jobs, const char *dir, const char *root_dir,
                    const char *root_file, int *have_root)
{
	DIR *d = opendir(dir);
	if (!d) {
		perror(dir);
		return -1;
	}

	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		char *child = NULL;
		if (path_join(dir, de->d_name, &child) != 0) {
			closedir(d);
			return -1;
		}

		struct stat st;
		if (stat(child, &st) != 0) {
			perror(child);
			free(child);
			closedir(d);
			return -1;
		}

		int rc = 0;
		if (S_ISDIR(st.st_mode))
			rc = walk_dir(jobs, child, root_dir, root_file, have_root);
		else if (S_ISREG(st.st_mode))
			rc = collect_file(jobs, child, root_dir, root_file, have_root);

		free(child);
		if (rc != 0) {
			closedir(d);
			return -1;
		}
	}
	closedir(d);
	return 0;
}

static int collect_listed(struct job_list *jobs, const char *line_in,
                          const char *base_dir, const char *root_file,
                          int *have_root)
{
	char *line = strdup(line_in);
	if (!line)
		return -1;

	size_t raw_len = 0;
	int skip = clean_list_path(line, &raw_len);
	if (skip < 0) {
		free(line);
		return -1;
	}
	if (skip > 0) {
		free(line);
		return 0;
	}

	char *arch = NULL;
	size_t arch_len = 0;
	if (weed_path_nfc(line, raw_len, &arch, &arch_len) != 0) {
		free(line);
		return -1;
	}

	char *disk = NULL;
	if (base_dir && base_dir[0]) {
		if (path_join(base_dir, line, &disk) != 0) {
			free(line);
			free(arch);
			return -1;
		}
	} else {
		disk = strdup(line);
		if (!disk) {
			free(line);
			free(arch);
			return -1;
		}
	}
	free(line);

	int rc = add_job(jobs, disk, arch, arch_len, root_file, have_root);
	free(disk);
	return rc;
}

static int run_pack_jobs(struct job_list *jobs, const char *out_path,
                         const char *key_path, unsigned compress_flags,
                         int have_root, const char *root_file)
{
	if (!have_root) {
		fprintf(stderr,
		        "weed: warning: root file \"%s\" not found at archive root; "
		        "no \"\" entry\n",
		        root_file ? root_file : WEED_DEFAULT_ROOT_FILE);
	}
	if (jobs->n == 0) {
		fprintf(stderr, "weed: empty file list\n");
		return -1;
	}

	promote_root_job(jobs);

	struct pack_ctx ctx;
	memset(&ctx, 0, sizeof ctx);
	ctx.compress_flags = compress_flags;

	ctx.out = fopen(out_path, "wb+");
	if (!ctx.out) {
		perror(out_path);
		return -1;
	}

	unsigned char zeros[WEED_SIG_SIZE];
	memset(zeros, 0, sizeof zeros);
	if (fwrite(zeros, 1, WEED_SIG_SIZE, ctx.out) != WEED_SIG_SIZE) {
		perror("fwrite sig");
		fclose(ctx.out);
		unlink(out_path);
		return -1;
	}

	for (size_t i = 0; i < jobs->n; i++) {
		if (stream_one_file(&ctx, &jobs->v[i]) != 0) {
			if (ctx.out)
				fclose(ctx.out);
			cat_free(&ctx.cat);
			unlink(out_path);
			return -1;
		}
	}

	if (finish_archive(&ctx, out_path, key_path) != 0) {
		if (ctx.out)
			fclose(ctx.out);
		cat_free(&ctx.cat);
		unlink(out_path);
		return -1;
	}
	cat_free(&ctx.cat);
	return 0;
}

int weed_pack(const char *root_dir, const char *out_path, const char *key_path,
              const char *root_file, unsigned compress_flags)
{
	if (!root_file || !root_file[0])
		root_file = WEED_DEFAULT_ROOT_FILE;
	if (ensure_root_file_ok(root_file) != 0)
		return -1;

	struct stat st;
	if (stat(root_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "weed: not a directory: %s\n", root_dir);
		return -1;
	}

	struct job_list jobs = {0};
	int have_root = 0;
	if (walk_dir(&jobs, root_dir, root_dir, root_file, &have_root) != 0) {
		jobs_free(&jobs);
		return -1;
	}

	int rc = run_pack_jobs(&jobs, out_path, key_path, compress_flags, have_root,
	                       root_file);
	jobs_free(&jobs);
	return rc;
}

int weed_pack_list(FILE *in, const char *base_dir, const char *out_path,
                   const char *key_path, const char *root_file,
                   unsigned compress_flags)
{
	if (!root_file || !root_file[0])
		root_file = WEED_DEFAULT_ROOT_FILE;
	if (ensure_root_file_ok(root_file) != 0)
		return -1;

	if (base_dir && base_dir[0]) {
		struct stat st;
		if (stat(base_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
			fprintf(stderr, "weed: -C is not a directory: %s\n", base_dir);
			return -1;
		}
	}

	struct job_list jobs = {0};
	int have_root = 0;
	char *line = NULL;
	size_t line_cap = 0;
	ssize_t nread;
	size_t lineno = 0;
	while ((nread = getline(&line, &line_cap, in)) != -1) {
		lineno++;
		if (collect_listed(&jobs, line, base_dir, root_file, &have_root) != 0) {
			fprintf(stderr, "weed: error at list line %zu\n", lineno);
			free(line);
			jobs_free(&jobs);
			return -1;
		}
	}
	free(line);

	if (ferror(in)) {
		perror("weed: reading file list");
		jobs_free(&jobs);
		return -1;
	}

	int rc = run_pack_jobs(&jobs, out_path, key_path, compress_flags, have_root,
	                       root_file);
	jobs_free(&jobs);
	return rc;
}
