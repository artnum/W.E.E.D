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

struct entry {
	char *disk_path; /* identity from disk when content == NULL */
	unsigned char *content; /* owned body (compressed twin or buffered) */
	int content_owned;
	char *arch_path;
	size_t arch_path_len;
	const char *mime;
	uint32_t mime_len;
	uint64_t content_len;
	uint8_t encoding;
	uint8_t cache_flags;
	uint32_t max_age;
	uint8_t etag[WEED_ETAG_SIZE];
	uint64_t hash;
	uint64_t offset;
	int is_root_doc;
};

struct entry_list {
	struct entry *v;
	size_t n;
	size_t cap;
};

static int list_push(struct entry_list *l, struct entry e)
{
	if (l->n == l->cap) {
		size_t ncap = l->cap ? l->cap * 2 : 64;
		struct entry *nv =
		    (struct entry *)realloc(l->v, ncap * sizeof(struct entry));
		if (!nv)
			return -1;
		l->v = nv;
		l->cap = ncap;
	}
	l->v[l->n++] = e;
	return 0;
}

static void list_free(struct entry_list *l)
{
	for (size_t i = 0; i < l->n; i++) {
		free(l->v[i].disk_path);
		free(l->v[i].arch_path);
		if (l->v[i].content_owned)
			free(l->v[i].content);
	}
	free(l->v);
	l->v = NULL;
	l->n = l->cap = 0;
}

static int cmp_index(const void *a, const void *b)
{
	const struct entry *ea = *(const struct entry *const *)a;
	const struct entry *eb = *(const struct entry *const *)b;
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

static int push_variant(struct entry_list *list, const char *disk_path,
                        char *arch, size_t arch_len, const char *mime,
                        uint8_t encoding, unsigned char *content,
                        size_t content_len, int content_owned,
                        uint8_t cache_flags, uint32_t max_age,
                        const uint8_t etag[WEED_ETAG_SIZE], int is_root)
{
	for (size_t i = 0; i < list->n; i++) {
		if (list->v[i].encoding == encoding &&
		    list->v[i].arch_path_len == arch_len &&
		    memcmp(list->v[i].arch_path, arch, arch_len) == 0) {
			fprintf(stderr,
			        "weed: duplicate path+encoding \"%.*s\" enc=%u\n",
			        (int)arch_len, arch, encoding);
			if (content_owned)
				free(content);
			return -1;
		}
	}

	struct entry e;
	memset(&e, 0, sizeof e);
	if (disk_path) {
		e.disk_path = strdup(disk_path);
		if (!e.disk_path) {
			if (content_owned)
				free(content);
			return -1;
		}
	}
	e.content = content;
	e.content_owned = content_owned;
	e.arch_path = arch;
	e.arch_path_len = arch_len;
	e.mime = mime;
	e.mime_len = (uint32_t)strlen(mime);
	e.content_len = (uint64_t)content_len;
	e.encoding = encoding;
	e.cache_flags = cache_flags;
	e.max_age = max_age;
	memcpy(e.etag, etag, WEED_ETAG_SIZE);
	e.hash = XXH64(arch, arch_len, WEED_XXH_SEED);
	e.is_root_doc = is_root && encoding == WEED_ENC_IDENTITY;

	if (list_push(list, e) != 0) {
		free(e.disk_path);
		if (content_owned)
			free(content);
		return -1;
	}
	return 0;
}

/*
 * Add identity (+ optional compressed twins). Takes ownership of arch on success
 * for the identity entry; twins get strdup'd arch copies.
 */
static int add_file_with_twins(struct entry_list *list, const char *disk_path,
                               char *arch, size_t arch_len,
                               const char *root_file, int *have_root,
                               unsigned compress_flags)
{
	struct stat st;
	if (stat(disk_path, &st) != 0) {
		perror(disk_path);
		free(arch);
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "weed: not a regular file: %s\n", disk_path);
		free(arch);
		return -1;
	}

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

	const char *mime = weed_mime_from_path(arch, arch_len);
	if (is_root)
		mime = "text/html";

	uint8_t cache_flags = WEED_CACHE_NO_CACHE;
	uint32_t max_age = 0;
	weed_cache_for_mime(mime, &cache_flags, &max_age);

	/* Always read body: ETag (xxh128) is over the stored content bytes. */
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	if (read_file_all(disk_path, &raw, &raw_len) != 0) {
		free(arch);
		return -1;
	}
	if ((uint64_t)raw_len != (uint64_t)st.st_size) {
		fprintf(stderr, "weed: size changed: %s\n", disk_path);
		free(raw);
		free(arch);
		return -1;
	}

	size_t path_len = arch_len;
	char *path_copy = (char *)malloc(path_len ? path_len : 1);
	if (!path_copy) {
		free(arch);
		free(raw);
		return -1;
	}
	if (path_len)
		memcpy(path_copy, arch, path_len);

	uint8_t etag_id[WEED_ETAG_SIZE];
	weed_etag_xxh128(raw, raw_len, etag_id);

	/* Identity streams from disk at write; etag already computed. */
	if (push_variant(list, disk_path, arch, arch_len, mime, WEED_ENC_IDENTITY,
	                 NULL, raw_len, 0, cache_flags, max_age, etag_id,
	                 is_root) != 0) {
		free(path_copy);
		free(raw);
		return -1;
	}

	if (compress_flags & WEED_COMPRESS_BR) {
		unsigned char *br = NULL;
		size_t br_len = 0;
		int rc = weed_compress_br(raw, raw_len, &br, &br_len);
		if (rc < 0) {
			fprintf(stderr, "weed: brotli failed for %s\n", disk_path);
			free(path_copy);
			free(raw);
			return -1;
		}
		if (rc == 0) {
			uint8_t etag_br[WEED_ETAG_SIZE];
			weed_etag_xxh128(br, br_len, etag_br);
			char *arch2 = (char *)malloc(path_len ? path_len : 1);
			if (!arch2) {
				free(br);
				free(path_copy);
				free(raw);
				return -1;
			}
			if (path_len)
				memcpy(arch2, path_copy, path_len);
			if (push_variant(list, NULL, arch2, path_len, mime, WEED_ENC_BR,
			                 br, br_len, 1, cache_flags, max_age, etag_br,
			                 is_root) != 0) {
				free(arch2);
				free(path_copy);
				free(raw);
				return -1;
			}
		}
	}

	if (compress_flags & WEED_COMPRESS_GZIP) {
		unsigned char *gz = NULL;
		size_t gz_len = 0;
		int rc = weed_compress_gzip(raw, raw_len, &gz, &gz_len);
		if (rc < 0) {
			fprintf(stderr, "weed: gzip failed for %s\n", disk_path);
			free(path_copy);
			free(raw);
			return -1;
		}
		if (rc == 0) {
			uint8_t etag_gz[WEED_ETAG_SIZE];
			weed_etag_xxh128(gz, gz_len, etag_gz);
			char *arch2 = (char *)malloc(path_len ? path_len : 1);
			if (!arch2) {
				free(gz);
				free(path_copy);
				free(raw);
				return -1;
			}
			if (path_len)
				memcpy(arch2, path_copy, path_len);
			if (push_variant(list, NULL, arch2, path_len, mime, WEED_ENC_GZIP,
			                 gz, gz_len, 1, cache_flags, max_age, etag_gz,
			                 is_root) != 0) {
				free(arch2);
				free(path_copy);
				free(raw);
				return -1;
			}
		}
	}

	free(path_copy);
	free(raw);
	return 0;
}

static int add_file_under_root(struct entry_list *list, const char *disk_path,
                               const char *root_dir, const char *root_file,
                               int *have_root, unsigned compress_flags)
{
	char *arch = NULL;
	size_t arch_len = 0;
	if (weed_relpath_nfc(root_dir, disk_path, &arch, &arch_len) != 0)
		return -1;
	return add_file_with_twins(list, disk_path, arch, arch_len, root_file,
	                           have_root, compress_flags);
}

static int walk_dir(struct entry_list *list, const char *dir,
                    const char *root_dir, const char *root_file, int *have_root,
                    unsigned compress_flags)
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
			rc = walk_dir(list, child, root_dir, root_file, have_root,
			              compress_flags);
		else if (S_ISREG(st.st_mode))
			rc = add_file_under_root(list, child, root_dir, root_file,
			                         have_root, compress_flags);

		free(child);
		if (rc != 0) {
			closedir(d);
			return -1;
		}
	}
	closedir(d);
	return 0;
}

static int add_listed_path(struct entry_list *list, const char *line_in,
                           const char *base_dir, const char *root_file,
                           int *have_root, unsigned compress_flags)
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

	int rc = add_file_with_twins(list, disk, arch, arch_len, root_file,
	                             have_root, compress_flags);
	free(disk);
	return rc;
}

static int write_content(FILE *out, struct entry *e)
{
	if (e->content) {
		if (e->content_len &&
		    fwrite(e->content, 1, (size_t)e->content_len, out) !=
		        (size_t)e->content_len) {
			perror("fwrite content");
			return -1;
		}
		return 0;
	}

	FILE *in = fopen(e->disk_path, "rb");
	if (!in) {
		perror(e->disk_path);
		return -1;
	}
	unsigned char buf[64 * 1024];
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
				perror(e->disk_path);
				fclose(in);
				return -1;
			}
			break;
		}
	}
	fclose(in);
	if (total != e->content_len) {
		fprintf(stderr, "weed: size changed while packing: %s\n",
		        e->disk_path);
		return -1;
	}
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

static void promote_root_first(struct entry_list *list, int have_root)
{
	if (!have_root)
		return;
	size_t ri = (size_t)-1;
	for (size_t i = 0; i < list->n; i++) {
		if (list->v[i].is_root_doc) {
			ri = i;
			break;
		}
	}
	if (ri != (size_t)-1 && ri != 0) {
		struct entry tmp = list->v[0];
		list->v[0] = list->v[ri];
		list->v[ri] = tmp;
	}
}

static int pack_entries(struct entry_list *list, const char *out_path,
                        const char *key_path, const char *root_file,
                        int have_root)
{
	if (!have_root) {
		fprintf(stderr,
		        "weed: warning: root file \"%s\" not found at archive root; "
		        "no \"\" entry\n",
		        root_file ? root_file : WEED_DEFAULT_ROOT_FILE);
	}

	promote_root_first(list, have_root);

	uint64_t n = (uint64_t)list->n;
	uint64_t hdr = weed_header_size(n);

	uint64_t off = hdr;
	for (size_t i = 0; i < list->n; i++) {
		if (list->v[i].arch_path_len > 0xffffffffu ||
		    list->v[i].mime_len > 0xffffffffu) {
			fprintf(stderr, "weed: path or mime too long\n");
			return -1;
		}
		list->v[i].offset = off;
		off += weed_fileitem_size((uint32_t)list->v[i].arch_path_len,
		                          list->v[i].mime_len, list->v[i].content_len);
	}

	struct entry **idx =
	    (struct entry **)malloc(list->n ? list->n * sizeof(*idx) : 1);
	if (!idx)
		return -1;
	for (size_t i = 0; i < list->n; i++)
		idx[i] = &list->v[i];
	qsort(idx, list->n, sizeof(*idx), cmp_index);

	FILE *out = fopen(out_path, "wb+");
	if (!out) {
		perror(out_path);
		free(idx);
		return -1;
	}

	unsigned char zeros[WEED_SIG_SIZE];
	memset(zeros, 0, sizeof zeros);
	if (fwrite(zeros, 1, WEED_SIG_SIZE, out) != WEED_SIG_SIZE) {
		perror("fwrite sig");
		goto fail;
	}

	unsigned char reserved[WEED_RESERVED_SIZE];
	memset(reserved, 0, sizeof reserved);
	reserved[0] = (unsigned char)WEED_VERSION; /* 8-bit format version */
	if (fwrite(reserved, 1, WEED_RESERVED_SIZE, out) != WEED_RESERVED_SIZE) {
		perror("fwrite reserved");
		goto fail;
	}

	if (weed_write_u64_le(out, n) != 0) {
		perror("fwrite file_count");
		goto fail;
	}

	for (size_t i = 0; i < list->n; i++) {
		if (weed_write_u64_le(out, idx[i]->hash) != 0) {
			perror("fwrite hash");
			goto fail;
		}
	}
	for (size_t i = 0; i < list->n; i++) {
		if (weed_write_u64_le(out, idx[i]->offset) != 0) {
			perror("fwrite offset");
			goto fail;
		}
	}

	size_t n_id = 0, n_br = 0, n_gz = 0;
	for (size_t i = 0; i < list->n; i++) {
		struct entry *e = &list->v[i];
		off_t pos = ftello(out);
		if (pos < 0 || (uint64_t)pos != e->offset) {
			fprintf(stderr,
			        "weed: internal offset mismatch for \"%.*s\" "
			        "(at %lld want %llu)\n",
			        (int)e->arch_path_len, e->arch_path, (long long)pos,
			        (unsigned long long)e->offset);
			goto fail;
		}

		if (weed_write_u64_le(out, e->content_len) != 0 ||
		    weed_write_u32_le(out, (uint32_t)e->arch_path_len) != 0 ||
		    weed_write_u32_le(out, e->mime_len) != 0) {
			perror("fwrite fileitem header");
			goto fail;
		}
		if (fputc((int)e->encoding, out) == EOF ||
		    fputc((int)e->cache_flags, out) == EOF) {
			perror("fwrite encoding/cache");
			goto fail;
		}
		if (weed_write_u32_le(out, e->max_age) != 0) {
			perror("fwrite max_age");
			goto fail;
		}
		if (fwrite(e->etag, 1, WEED_ETAG_SIZE, out) != WEED_ETAG_SIZE) {
			perror("fwrite etag");
			goto fail;
		}
		if (e->arch_path_len &&
		    fwrite(e->arch_path, 1, e->arch_path_len, out) != e->arch_path_len) {
			perror("fwrite path");
			goto fail;
		}
		if (fwrite(e->mime, 1, e->mime_len, out) != e->mime_len) {
			perror("fwrite mime");
			goto fail;
		}
		if (write_content(out, e) != 0)
			goto fail;

		if (e->encoding == WEED_ENC_IDENTITY)
			n_id++;
		else if (e->encoding == WEED_ENC_BR)
			n_br++;
		else if (e->encoding == WEED_ENC_GZIP)
			n_gz++;
	}

	if (fflush(out) != 0) {
		perror("fflush");
		goto fail;
	}
	fclose(out);
	out = NULL;
	free(idx);
	idx = NULL;

	if (weed_sign_file(key_path, out_path) != 0)
		return -1;

	fprintf(stderr,
	        "weed: packed %llu item(s) (identity=%zu br=%zu gzip=%zu) -> %s\n",
	        (unsigned long long)n, n_id, n_br, n_gz, out_path);
	return 0;

fail:
	if (out)
		fclose(out);
	free(idx);
	unlink(out_path);
	return -1;
}

int weed_pack(const char *root_dir, const char *out_path, const char *key_path,
              const char *root_file, unsigned compress_flags)
{
	if (!root_file || !root_file[0])
		root_file = WEED_DEFAULT_ROOT_FILE;
	if (ensure_root_file_ok(root_file) != 0)
		return -1;

	struct entry_list list = {0};
	int have_root = 0;

	struct stat st;
	if (stat(root_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "weed: not a directory: %s\n", root_dir);
		return -1;
	}

	if (walk_dir(&list, root_dir, root_dir, root_file, &have_root,
	             compress_flags) != 0) {
		list_free(&list);
		return -1;
	}

	int rc = pack_entries(&list, out_path, key_path, root_file, have_root);
	list_free(&list);
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

	struct entry_list list = {0};
	int have_root = 0;

	char *line = NULL;
	size_t line_cap = 0;
	ssize_t nread;
	size_t lineno = 0;
	while ((nread = getline(&line, &line_cap, in)) != -1) {
		lineno++;
		if (add_listed_path(&list, line, base_dir, root_file, &have_root,
		                    compress_flags) != 0) {
			fprintf(stderr, "weed: error at list line %zu\n", lineno);
			free(line);
			list_free(&list);
			return -1;
		}
	}
	free(line);

	if (ferror(in)) {
		perror("weed: reading file list");
		list_free(&list);
		return -1;
	}

	if (list.n == 0) {
		fprintf(stderr, "weed: empty file list\n");
		list_free(&list);
		return -1;
	}

	int rc = pack_entries(&list, out_path, key_path, root_file, have_root);
	list_free(&list);
	return rc;
}
