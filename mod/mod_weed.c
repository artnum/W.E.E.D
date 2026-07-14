/*
 * mod_weed — serve static assets from a signed Weed archive.
 *
 *   LoadModule weed_module modules/mod_weed.so
 *
 *   <Location /app>
 *       SetHandler weed
 *       WeedArchive    /var/www/app.weed
 *       WeedPublicKey  /etc/weed/app.pub.pem
 *       WeedSpa        On   # optional: unknown routes → root doc ""
 *   </Location>
 *
 * Startup: verify RSA-4096/SHA-256 signature, then mmap(2) the whole archive
 * MAP_SHARED / PROT_READ (via apr_mmap APR_MMAP_READ). The path-hash index and
 * payload live in that single mapping — shared physical pages across workers,
 * no per-request open/seek, no separate shm copy of the index.
 *
 * Request: URI → NFC path → xxHash64 → binary search in the map → bucket from
 * the same mmap. With WeedSpa On, a miss without a file extension serves "".
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"

#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_mmap.h"
#include "apr_buckets.h"
#include "apr_date.h"
#include "apr_lib.h"

#include "weed.h"
#include "weed_format.h"

#include <xxhash.h>

#include <string.h>
#include <strings.h>
#include <stdint.h>

module AP_MODULE_DECLARE_DATA weed_module;

/* ---------- runtime (one per unique archive path) ---------- */

typedef struct weed_runtime {
	const char *archive_path;
	const char *pubkey_path;
	apr_file_t *file; /* kept open for the lifetime of the mmap */
	apr_mmap_t *mm;   /* whole archive, APR_MMAP_READ (~ MAP_SHARED|PROT_READ) */
	const unsigned char *base;
	apr_size_t size;
	uint64_t n;
	const uint64_t *hashes;  /* into mmap, LE on wire = host on LE */
	const uint64_t *offsets; /* into mmap */
	apr_time_t loaded_at;    /* Last-Modified for all items = module load time */
	char *last_modified;     /* HTTP-date, pool-allocated */
	struct weed_runtime *next;
} weed_runtime;

#define WEED_SPA_UNSET (-1)
#define WEED_SPA_OFF   0
#define WEED_SPA_ON    1

typedef struct {
	const char *archive_path;
	const char *pubkey_path;
	const char *location;
	int spa;
	weed_runtime *rt;
} weed_dir_cfg;

typedef struct weed_pending {
	weed_dir_cfg *cfg;
	server_rec *s;
	struct weed_pending *next;
} weed_pending;

static weed_runtime *weed_runtimes = NULL;
static weed_pending *weed_pending_list = NULL;

/* ---------- LE helpers ---------- */

static uint32_t weed_load_u32_le(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t weed_load_u64_le(const unsigned char *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

/* ---------- config ---------- */

static void *weed_create_dir_config(apr_pool_t *p, char *dir)
{
	weed_dir_cfg *cfg = apr_pcalloc(p, sizeof(*cfg));
	cfg->location = dir;
	cfg->spa = WEED_SPA_UNSET;
	return cfg;
}

static void *weed_merge_dir_config(apr_pool_t *p, void *basev, void *addv)
{
	weed_dir_cfg *base = basev;
	weed_dir_cfg *add = addv;
	weed_dir_cfg *m = apr_pcalloc(p, sizeof(*m));
	m->archive_path =
	    add->archive_path ? add->archive_path : base->archive_path;
	m->pubkey_path = add->pubkey_path ? add->pubkey_path : base->pubkey_path;
	m->location = add->location ? add->location : base->location;
	m->spa = (add->spa != WEED_SPA_UNSET) ? add->spa : base->spa;
	m->rt = add->rt ? add->rt : base->rt;
	return m;
}

static void weed_register_pending(apr_pool_t *p, server_rec *s, weed_dir_cfg *cfg)
{
	for (weed_pending *q = weed_pending_list; q; q = q->next) {
		if (q->cfg == cfg)
			return;
	}
	weed_pending *node = apr_pcalloc(p, sizeof(*node));
	node->cfg = cfg;
	node->s = s;
	node->next = weed_pending_list;
	weed_pending_list = node;
}

static const char *cmd_weed_archive(cmd_parms *cmd, void *mconfig,
                                    const char *arg)
{
	weed_dir_cfg *cfg = mconfig;
	cfg->archive_path = ap_server_root_relative(cmd->pool, arg);
	weed_register_pending(cmd->pool, cmd->server, cfg);
	return NULL;
}

static const char *cmd_weed_pubkey(cmd_parms *cmd, void *mconfig,
                                   const char *arg)
{
	weed_dir_cfg *cfg = mconfig;
	cfg->pubkey_path = ap_server_root_relative(cmd->pool, arg);
	weed_register_pending(cmd->pool, cmd->server, cfg);
	return NULL;
}

static const char *cmd_weed_spa(cmd_parms *cmd, void *mconfig, int on)
{
	(void)cmd;
	weed_dir_cfg *cfg = mconfig;
	cfg->spa = on ? WEED_SPA_ON : WEED_SPA_OFF;
	return NULL;
}

static const command_rec weed_cmds[] = {
    AP_INIT_TAKE1("WeedArchive", cmd_weed_archive, NULL, ACCESS_CONF | OR_AUTHCFG,
                  "Path to the .weed archive to serve"),
    AP_INIT_TAKE1("WeedPublicKey", cmd_weed_pubkey, NULL, ACCESS_CONF | OR_AUTHCFG,
                  "PEM public key (RSA-4096) used to verify the archive"),
    AP_INIT_FLAG("WeedSpa", cmd_weed_spa, NULL, ACCESS_CONF | OR_AUTHCFG,
                 "On: serve root document (\"\") for unknown paths without a "
                 "file extension (SPA client-side routes)"),
    {NULL}};

/* ---------- load archive: verify + mmap whole file ---------- */

static weed_runtime *weed_find_runtime(const char *path)
{
	for (weed_runtime *r = weed_runtimes; r; r = r->next) {
		if (strcmp(r->archive_path, path) == 0)
			return r;
	}
	return NULL;
}

static weed_runtime *weed_load_runtime(apr_pool_t *p, server_rec *s,
                                       const char *archive_path,
                                       const char *pubkey_path)
{
	weed_runtime *existing = weed_find_runtime(archive_path);
	if (existing)
		return existing;

	if (weed_verify_file(pubkey_path, archive_path) != 0) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
		             "mod_weed: signature verification failed for %s",
		             archive_path);
		return NULL;
	}

	apr_file_t *file = NULL;
	apr_status_t rv =
	    apr_file_open(&file, archive_path, APR_FOPEN_READ | APR_FOPEN_BINARY,
	                  APR_OS_DEFAULT, p);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
		             "mod_weed: cannot open %s", archive_path);
		return NULL;
	}

	apr_finfo_t finfo;
	rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, file);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
		             "mod_weed: fstat %s", archive_path);
		return NULL;
	}

	if ((apr_uint64_t)finfo.size <
	    (apr_uint64_t)WEED_SIG_SIZE + WEED_RESERVED_SIZE + 8ull) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
		             "mod_weed: archive too small: %s", archive_path);
		return NULL;
	}

	/* Entire package in one shared read-only mapping. */
	apr_mmap_t *mm = NULL;
	rv = apr_mmap_create(&mm, file, 0, (apr_size_t)finfo.size, APR_MMAP_READ,
	                     p);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
		             "mod_weed: mmap failed for %s (size=%" APR_OFF_T_FMT ")",
		             archive_path, finfo.size);
		return NULL;
	}

	/* apr_mmap_t is a public struct; mm is the MAP_SHARED mapping base. */
	const unsigned char *base = (const unsigned char *)mm->mm;
	apr_size_t size = mm->size;
	if (!base || size != (apr_size_t)finfo.size) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
		             "mod_weed: bad mmap region for %s", archive_path);
		return NULL;
	}

	/* reserved[0] = format version (8 bits of the 128-bit reserved area). */
	uint8_t ver = base[WEED_SIG_SIZE];
	if (ver != WEED_VERSION) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
		             "mod_weed: unsupported archive version %u in %s "
		             "(want %u)",
		             (unsigned)ver, archive_path, (unsigned)WEED_VERSION);
		return NULL;
	}

	uint64_t n =
	    weed_load_u64_le(base + WEED_SIG_SIZE + WEED_RESERVED_SIZE);
	uint64_t hdr = weed_header_size(n);

	if ((uint64_t)size < hdr) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
		             "mod_weed: truncated header in %s (n=%" APR_UINT64_T_FMT ")",
		             archive_path, n);
		return NULL;
	}
	if (n > (UINT64_C(1) << 32)) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
		             "mod_weed: unreasonable file_count in %s", archive_path);
		return NULL;
	}

	const uint64_t *hashes =
	    (const uint64_t *)(base + WEED_SIG_SIZE + WEED_RESERVED_SIZE + 8);
	const uint64_t *offsets = hashes + n;

	for (uint64_t i = 0; i < n; i++) {
		if (offsets[i] < hdr || offsets[i] >= (uint64_t)size) {
			ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
			             "mod_weed: bad offset[%" APR_UINT64_T_FMT "]=%" APR_UINT64_T_FMT
			             " in %s",
			             i, offsets[i], archive_path);
			return NULL;
		}
	}

	weed_runtime *rt = apr_pcalloc(p, sizeof(*rt));
	rt->archive_path = apr_pstrdup(p, archive_path);
	rt->pubkey_path = apr_pstrdup(p, pubkey_path);
	rt->file = file;
	rt->mm = mm;
	rt->base = base;
	rt->size = size;
	rt->n = n;
	rt->hashes = hashes;
	rt->offsets = offsets;
	rt->loaded_at = apr_time_now();
	/* RFC 7231 HTTP-date for Last-Modified (same for every object in this map). */
	rt->last_modified = apr_palloc(p, APR_RFC822_DATE_LEN);
	if (apr_rfc822_date(rt->last_modified, rt->loaded_at) != APR_SUCCESS)
		rt->last_modified = NULL;
	rt->next = weed_runtimes;
	weed_runtimes = rt;

	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
	             "mod_weed: mmap'd %s (%" APR_UINT64_T_FMT " entries, %" APR_SIZE_T_FMT
	             " bytes, shared read-only)",
	             archive_path, n, size);
	return rt;
}

static int weed_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp)
{
	(void)pconf;
	(void)plog;
	(void)ptemp;
	weed_pending_list = NULL;
	weed_runtimes = NULL;
	return OK;
}

static int weed_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp, server_rec *s)
{
	(void)plog;
	(void)ptemp;

	if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
		return OK;

	weed_runtimes = NULL;

	for (weed_pending *q = weed_pending_list; q; q = q->next) {
		weed_dir_cfg *cfg = q->cfg;
		if (!cfg->archive_path || !cfg->pubkey_path) {
			ap_log_error(APLOG_MARK, APLOG_EMERG, 0, q->s,
			             "mod_weed: both WeedArchive and WeedPublicKey are "
			             "required");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		weed_runtime *rt =
		    weed_load_runtime(pconf, q->s, cfg->archive_path, cfg->pubkey_path);
		if (!rt)
			return HTTP_INTERNAL_SERVER_ERROR;
		cfg->rt = rt;
	}

	(void)s;
	return OK;
}

/* ---------- path helpers ---------- */

static int weed_has_dotdot(const char *p, size_t n)
{
	size_t i = 0;
	while (i < n) {
		if (p[i] == '.' && i + 1 < n && p[i + 1] == '.' &&
		    (i + 2 == n || p[i + 2] == '/') && (i == 0 || p[i - 1] == '/'))
			return 1;
		i++;
	}
	return 0;
}

static char *weed_request_relpath(request_rec *r, weed_dir_cfg *cfg)
{
	const char *uri = r->uri;
	if (!uri)
		return NULL;

	const char *base = cfg->location ? cfg->location : "/";
	size_t blen = strlen(base);
	while (blen > 1 && base[blen - 1] == '/')
		blen--;

	size_t ulen = strlen(uri);
	const char *rel;
	if (blen == 0 || (blen == 1 && base[0] == '/')) {
		rel = uri;
	} else {
		if (ulen < blen || strncmp(uri, base, blen) != 0)
			return NULL;
		if (ulen > blen && uri[blen] != '/')
			return NULL;
		rel = uri + blen;
	}

	while (*rel == '/')
		rel++;

	char *path = apr_pstrdup(r->pool, rel);
	char *q = strchr(path, '?');
	if (q)
		*q = '\0';

	if (ap_unescape_url(path) != OK)
		return NULL;

	if (weed_has_dotdot(path, strlen(path)))
		return NULL;

	while (path[0] == '/')
		path++;

	return path;
}

/* ---------- Accept-Encoding + index lookup in mmap ---------- */

/* True if coding appears as a token and is not explicitly q=0. */
static int weed_ae_wants(const char *ae, const char *coding)
{
	if (!ae || !coding)
		return 0;
	size_t nlen = strlen(coding);
	const char *p = ae;
	while (*p) {
		while (*p == ' ' || *p == ',' || *p == '\t')
			p++;
		if (!*p)
			break;
		if (strncasecmp(p, coding, nlen) == 0 &&
		    (p[nlen] == '\0' || p[nlen] == ',' || p[nlen] == ';' ||
		     p[nlen] == ' ' || p[nlen] == '\t')) {
			const char *q = p + nlen;
			while (*q == ' ' || *q == '\t')
				q++;
			if (*q == ';') {
				/* crude q=0 detection */
				const char *r = q + 1;
				while (*r && *r != ',') {
					if ((*r == 'q' || *r == 'Q') && r[1] == '=') {
						r += 2;
						while (*r == ' ' || *r == '\t')
							r++;
						if (*r == '0' &&
						    (r[1] == '\0' || r[1] == ',' || r[1] == ' ' ||
						     r[1] == '\t' || r[1] == ';'))
							return 0;
						if (*r == '0' && r[1] == '.' && r[2] == '0')
							return 0;
						break;
					}
					r++;
				}
			}
			return 1;
		}
		while (*p && *p != ',')
			p++;
	}
	return 0;
}

typedef struct weed_hit {
	int64_t idx;
	uint64_t clen;
	apr_off_t coff;
	const char *mime;
	uint32_t mlen;
	uint8_t enc;
	uint8_t cache_flags;
	uint32_t max_age;
	const uint8_t *etag; /* 16 bytes in mmap */
} weed_hit;

/*
 * FILEITEM: clen|plen|mlen|enc|cache_flags|max_age|etag[16]|path|mime|body
 * Prefer br > gzip > identity among twins for this path.
 */
static int64_t weed_lookup(weed_runtime *rt, const char *path, size_t path_len,
                           int want_br, int want_gz, weed_hit *hit_out,
                           apr_pool_t *pool)
{
	uint64_t h = XXH64(path, path_len, WEED_XXH_SEED);
	const uint64_t *hashes = rt->hashes;
	uint64_t n = rt->n;
	const unsigned char *base = rt->base;
	uint64_t size = (uint64_t)rt->size;

	int64_t lo = 0, hi = (int64_t)n - 1, found = -1;
	while (lo <= hi) {
		int64_t mid = lo + (hi - lo) / 2;
		if (hashes[mid] < h)
			lo = mid + 1;
		else if (hashes[mid] > h)
			hi = mid - 1;
		else {
			found = mid;
			break;
		}
	}
	if (found < 0)
		return -1;

	int64_t left = found;
	while (left > 0 && hashes[left - 1] == h)
		left--;
	int64_t right = found;
	while (right + 1 < (int64_t)n && hashes[right + 1] == h)
		right++;

	weed_hit id = {0}, br = {0}, gz = {0};
	id.idx = br.idx = gz.idx = -1;

	for (int64_t i = left; i <= right; i++) {
		uint64_t foff = rt->offsets[i];
		if (foff + (uint64_t)WEED_ITEM_HDR_SIZE > size)
			continue;

		const unsigned char *item = base + foff;
		uint64_t clen = weed_load_u64_le(item);
		uint32_t plen = weed_load_u32_le(item + 8);
		uint32_t mlen = weed_load_u32_le(item + 12);
		uint8_t enc = item[16];
		uint8_t cflags = item[17];
		uint32_t max_age = weed_load_u32_le(item + 18);
		const uint8_t *etag = item + 22;

		if (foff + (uint64_t)WEED_ITEM_HDR_SIZE + plen + mlen + clen > size)
			continue;

		const unsigned char *pbytes = item + WEED_ITEM_HDR_SIZE;
		if (plen != path_len || memcmp(pbytes, path, path_len) != 0)
			continue;

		const unsigned char *mbytes = pbytes + plen;
		weed_hit cur;
		cur.idx = i;
		cur.clen = clen;
		cur.coff = (apr_off_t)(foff + WEED_ITEM_HDR_SIZE + plen + mlen);
		cur.mime = (const char *)mbytes;
		cur.mlen = mlen;
		cur.enc = enc;
		cur.cache_flags = cflags;
		cur.max_age = max_age;
		cur.etag = etag;

		if (enc == WEED_ENC_BR)
			br = cur;
		else if (enc == WEED_ENC_GZIP)
			gz = cur;
		else
			id = cur;
	}

	weed_hit pick;
	memset(&pick, 0, sizeof pick);
	pick.idx = -1;

	if (want_br && br.idx >= 0)
		pick = br;
	else if (want_gz && gz.idx >= 0)
		pick = gz;
	else if (id.idx >= 0)
		pick = id;
	else
		return -1;

	*hit_out = pick;
	(void)pool;
	return pick.idx;
}

static char *weed_format_etag(apr_pool_t *p, const uint8_t etag[WEED_ETAG_SIZE])
{
	/* Strong ETag: quoted 32-char lowercase hex of xxh128. */
	char *s = apr_palloc(p, 2 + 32 + 1);
	s[0] = '"';
	static const char hex[] = "0123456789abcdef";
	for (unsigned i = 0; i < WEED_ETAG_SIZE; i++) {
		s[1 + 2 * i] = hex[etag[i] >> 4];
		s[2 + 2 * i] = hex[etag[i] & 0xf];
	}
	s[1 + 32] = '"';
	s[2 + 32] = '\0';
	return s;
}

static char *weed_format_cache_control(apr_pool_t *p, uint8_t flags,
                                       uint32_t max_age)
{
	/* Build Cache-Control from pack-time flags + max_age. */
	char *buf = apr_palloc(p, 128);
	size_t o = 0;
	buf[0] = '\0';

	if (flags & WEED_CACHE_NO_STORE)
		o += (size_t)sprintf(buf + o, "%s%s", o ? ", " : "", "no-store");
	if (flags & WEED_CACHE_NO_CACHE)
		o += (size_t)sprintf(buf + o, "%s%s", o ? ", " : "", "no-cache");
	if (flags & WEED_CACHE_PUBLIC)
		o += (size_t)sprintf(buf + o, "%s%s", o ? ", " : "", "public");
	if (flags & WEED_CACHE_PRIVATE)
		o += (size_t)sprintf(buf + o, "%s%s", o ? ", " : "", "private");
	if (flags & WEED_CACHE_MUST_REVAL)
		o += (size_t)sprintf(buf + o, "%s%s", o ? ", " : "", "must-revalidate");
	if (flags & WEED_CACHE_IMMUTABLE)
		o += (size_t)sprintf(buf + o, "%s%s", o ? ", " : "", "immutable");

	/* Always emit max-age (default 0 with no-cache). */
	o += (size_t)sprintf(buf + o, "%smax-age=%u", o ? ", " : "", max_age);
	(void)o;
	return buf;
}

/* If-None-Match: any strong tag match → 304. */
static int weed_etag_matches(const char *inm, const char *etag)
{
	if (!inm || !etag)
		return 0;
	if (strcmp(inm, "*") == 0)
		return 1;
	/* Walk comma-separated list; ignore weak W/ prefix for comparison. */
	const char *p = inm;
	size_t elen = strlen(etag);
	while (*p) {
		while (*p == ' ' || *p == ',')
			p++;
		if (!*p)
			break;
		if (p[0] == 'W' && p[1] == '/')
			p += 2;
		while (*p == ' ')
			p++;
		if (strncmp(p, etag, elen) == 0 &&
		    (p[elen] == '\0' || p[elen] == ',' || p[elen] == ' '))
			return 1;
		while (*p && *p != ',')
			p++;
	}
	return 0;
}

static int weed_path_has_extension(const char *path, size_t len)
{
	const char *base = path;
	for (size_t i = 0; i < len; i++) {
		if (path[i] == '/')
			base = path + i + 1;
	}
	size_t blen = (size_t)(path + len - base);
	for (size_t i = 0; i < blen; i++) {
		if (base[i] == '.')
			return 1;
	}
	return 0;
}

/* ---------- handler ---------- */

static int weed_handler(request_rec *r)
{
	if (!r->handler || strcmp(r->handler, "weed") != 0)
		return DECLINED;

	if (r->method_number != M_GET && r->method_number != M_OPTIONS)
		return HTTP_METHOD_NOT_ALLOWED;

	if (r->method_number == M_OPTIONS) {
		apr_table_setn(r->headers_out, "Allow", "GET, HEAD, OPTIONS");
		ap_set_content_length(r, 0);
		return OK;
	}

	weed_dir_cfg *cfg =
	    ap_get_module_config(r->per_dir_config, &weed_module);
	if (!cfg || !cfg->archive_path || !cfg->pubkey_path) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		              "mod_weed: WeedArchive/WeedPublicKey not configured");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	weed_runtime *rt = cfg->rt;
	if (!rt) {
		rt = weed_find_runtime(cfg->archive_path);
		if (!rt) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			              "mod_weed: archive not loaded: %s",
			              cfg->archive_path);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		cfg->rt = rt;
	}

	if (!rt->mm || !rt->base) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		              "mod_weed: archive not mapped");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char *rel = weed_request_relpath(r, cfg);
	if (!rel)
		return HTTP_BAD_REQUEST;

	char *nfc = NULL;
	size_t nfc_len = 0;
	if (weed_path_nfc(rel, strlen(rel), &nfc, &nfc_len) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		              "mod_weed: NFC normalization failed");
		return HTTP_BAD_REQUEST;
	}

	const char *ae = apr_table_get(r->headers_in, "Accept-Encoding");
	int want_br = weed_ae_wants(ae, "br");
	int want_gz = weed_ae_wants(ae, "gzip");

	weed_hit hit;
	memset(&hit, 0, sizeof hit);
	hit.idx = -1;
	int64_t idx = weed_lookup(rt, nfc, nfc_len, want_br, want_gz, &hit, r->pool);

	if (idx < 0 && cfg->spa == WEED_SPA_ON &&
	    !weed_path_has_extension(nfc, nfc_len)) {
		idx = weed_lookup(rt, "", 0, want_br, want_gz, &hit, r->pool);
		if (idx >= 0) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			              "mod_weed: SPA fallback for \"%s\" → root doc",
			              nfc);
		}
	}
	free(nfc);

	if (idx < 0)
		return HTTP_NOT_FOUND;

	char *mime = apr_pstrmemdup(r->pool, hit.mime, hit.mlen);
	char *etag = weed_format_etag(r->pool, hit.etag);
	char *cc =
	    weed_format_cache_control(r->pool, hit.cache_flags, hit.max_age);

	ap_set_content_type(r, mime);
	ap_set_content_length(r, (apr_off_t)hit.clen);
	apr_table_setn(r->headers_out, "ETag", etag);
	apr_table_setn(r->headers_out, "Cache-Control", cc);
	if (rt->last_modified)
		apr_table_setn(r->headers_out, "Last-Modified", rt->last_modified);
	apr_table_mergen(r->headers_out, "Vary", "Accept-Encoding");
	{
		const char *enc_name = weed_enc_name(hit.enc);
		if (enc_name)
			apr_table_setn(r->headers_out, "Content-Encoding", enc_name);
	}

	/* Validators: If-None-Match wins over If-Modified-Since (RFC 7232). */
	const char *inm = apr_table_get(r->headers_in, "If-None-Match");
	if (inm && weed_etag_matches(inm, etag)) {
		apr_table_unset(r->headers_out, "Content-Length");
		return HTTP_NOT_MODIFIED;
	}
	if (!inm) {
		const char *ims = apr_table_get(r->headers_in, "If-Modified-Since");
		if (ims) {
			apr_time_t ims_t = apr_date_parse_http(ims);
			if (ims_t != APR_DATE_BAD && ims_t >= rt->loaded_at) {
				apr_table_unset(r->headers_out, "Content-Length");
				return HTTP_NOT_MODIFIED;
			}
		}
	}

	if (r->header_only || hit.clen == 0)
		return OK;

	uint64_t content_len = hit.clen;
	apr_off_t content_off = hit.coff;

	/*
	 * Stream from the shared mmap. Use immortal buckets (not apr_bucket_mmap):
	 * the mapping is process-lifetime / pool-pconf; mmap buckets can drop the
	 * last ref and munmap the archive out from under us after the brigade runs.
	 * Immortal = "this pointer stays valid" → true zero-copy, no seek races.
	 */
	apr_bucket_brigade *bb =
	    apr_brigade_create(r->pool, r->connection->bucket_alloc);

	const apr_size_t chunk_max = (apr_size_t)1 << 30;
	apr_off_t off = content_off;
	uint64_t left = content_len;
	while (left > 0) {
		apr_size_t chunk =
		    left > (uint64_t)chunk_max ? chunk_max : (apr_size_t)left;
		const char *ptr = (const char *)(rt->base + (apr_size_t)off);
		apr_bucket *b = apr_bucket_immortal_create(
		    ptr, chunk, r->connection->bucket_alloc);
		if (!b) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			              "mod_weed: apr_bucket_immortal_create failed");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		APR_BRIGADE_INSERT_TAIL(bb, b);
		off += (apr_off_t)chunk;
		left -= chunk;
	}
	APR_BRIGADE_INSERT_TAIL(
	    bb, apr_bucket_eos_create(r->connection->bucket_alloc));

	apr_status_t rv = ap_pass_brigade(r->output_filters, bb);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		              "mod_weed: ap_pass_brigade failed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}

/* ---------- hooks ---------- */

static void weed_register_hooks(apr_pool_t *p)
{
	(void)p;
	ap_hook_pre_config(weed_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(weed_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(weed_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA weed_module = {
    STANDARD20_MODULE_STUFF,
    weed_create_dir_config,
    weed_merge_dir_config,
    NULL,
    NULL,
    weed_cmds,
    weed_register_hooks};
