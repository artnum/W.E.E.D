#define _POSIX_C_SOURCE 200809L

#include "weed_index.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <xxhash.h>

uint32_t weed_load_u32_le(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

uint64_t weed_load_u64_le(const unsigned char *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

int weed_map_from_buffer(const unsigned char *base, uint64_t size, weed_map *out)
{
	if (!base || !out)
		return -1;
	if (size < (uint64_t)WEED_SIG_SIZE + weed_header_size(0))
		return -1;

	uint64_t n = weed_load_u64_le(base + size - 8);
	if (n > (UINT64_C(1) << 32))
		return -1;

	uint64_t hdr_sz = weed_header_size(n);
	if (size < (uint64_t)WEED_SIG_SIZE + hdr_sz)
		return -1;

	uint64_t header_start = size - hdr_sz;
	const uint64_t *hashes = (const uint64_t *)(base + header_start);
	const uint64_t *offsets = hashes + n;
	const unsigned char *reserved = base + header_start + 16ull * n;

	if (reserved[0] != WEED_VERSION)
		return -1;

	for (uint64_t i = 0; i < n; i++) {
		if (offsets[i] < (uint64_t)WEED_SIG_SIZE || offsets[i] >= header_start)
			return -1;
	}

	out->base = base;
	out->size = size;
	out->n = n;
	out->header_start = header_start;
	out->hashes = hashes;
	out->offsets = offsets;
	return 0;
}

int weed_ae_wants(const char *ae, const char *coding)
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

int64_t weed_lookup(const weed_map *m, const char *path, size_t path_len,
                    int want_br, int want_gz, weed_hit *hit_out)
{
	if (!m || !m->base || !hit_out)
		return -1;

	uint64_t h = XXH64(path, path_len, WEED_XXH_SEED);
	const uint64_t *hashes = m->hashes;
	uint64_t n = m->n;
	const unsigned char *base = m->base;
	uint64_t size = m->size;

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
		uint64_t foff = m->offsets[i];
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
		cur.content_off = foff + WEED_ITEM_HDR_SIZE + plen + mlen;
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
	return pick.idx;
}

void weed_format_etag(const uint8_t etag[WEED_ETAG_SIZE], char *out)
{
	static const char hex[] = "0123456789abcdef";
	out[0] = '"';
	for (unsigned i = 0; i < WEED_ETAG_SIZE; i++) {
		out[1 + 2 * i] = hex[etag[i] >> 4];
		out[2 + 2 * i] = hex[etag[i] & 0xf];
	}
	out[1 + 32] = '"';
	out[2 + 32] = '\0';
}

void weed_format_cache_control(uint8_t flags, uint32_t max_age, char *out,
                               size_t out_len)
{
	if (!out || out_len == 0)
		return;
	out[0] = '\0';
	size_t o = 0;

	#define APPEND(lit)                                                            \
		do {                                                                   \
			const char *s_ = (lit);                                        \
			size_t n_ = strlen(s_);                                         \
			if (o && o + 2 < out_len) {                                    \
				out[o++] = ',';                                        \
				out[o++] = ' ';                                        \
			}                                                              \
			if (o + n_ < out_len) {                                        \
				memcpy(out + o, s_, n_);                               \
				o += n_;                                               \
				out[o] = '\0';                                          \
			}                                                              \
		} while (0)

	if (flags & WEED_CACHE_NO_STORE)
		APPEND("no-store");
	if (flags & WEED_CACHE_NO_CACHE)
		APPEND("no-cache");
	if (flags & WEED_CACHE_PUBLIC)
		APPEND("public");
	if (flags & WEED_CACHE_PRIVATE)
		APPEND("private");
	if (flags & WEED_CACHE_MUST_REVAL)
		APPEND("must-revalidate");
	if (flags & WEED_CACHE_IMMUTABLE)
		APPEND("immutable");

	char ma[32];
	snprintf(ma, sizeof ma, "max-age=%u", max_age);
	APPEND(ma);
	#undef APPEND
}

int weed_etag_matches(const char *inm, const char *etag)
{
	if (!inm || !etag)
		return 0;
	if (strcmp(inm, "*") == 0)
		return 1;
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

int weed_path_has_extension(const char *path, size_t len)
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

int weed_has_dotdot(const char *p, size_t n)
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
