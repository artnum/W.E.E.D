#ifndef WEED_INDEX_H
#define WEED_INDEX_H

/*
 * Pure archive-index / serve helpers used by mod_weed (and unit tests).
 * No Apache dependency.
 */

#include "weed_format.h"

#include <stddef.h>
#include <stdint.h>

typedef struct weed_map {
	const unsigned char *base;
	uint64_t size;
	uint64_t n;
	uint64_t header_start; /* payload ends here; LE header starts here */
	const uint64_t *hashes;
	const uint64_t *offsets;
} weed_map;

typedef struct weed_hit {
	int64_t idx;
	uint64_t clen;
	uint64_t content_off; /* absolute offset of body bytes in the map */
	const char *mime;
	uint32_t mlen;
	uint8_t enc;
	uint8_t cache_flags;
	uint32_t max_age;
	const uint8_t *etag; /* WEED_ETAG_SIZE bytes into map */
} weed_hit;

/* Parse LE header at EOF; 0 ok, -1 bad. Does not verify signature. */
int weed_map_from_buffer(const unsigned char *base, uint64_t size, weed_map *out);

/* Accept-Encoding token; 1 if coding wanted (not q=0). */
int weed_ae_wants(const char *ae, const char *coding);

/*
 * Binary search path; pick br > gzip > identity among twins.
 * Returns index or -1.
 */
int64_t weed_lookup(const weed_map *m, const char *path, size_t path_len,
                    int want_br, int want_gz, weed_hit *hit_out);

/* out must hold at least 35 bytes: '"' + 32 hex + '"' + NUL */
void weed_format_etag(const uint8_t etag[WEED_ETAG_SIZE], char *out);

/* out_len should be >= 128 */
void weed_format_cache_control(uint8_t flags, uint32_t max_age, char *out,
                               size_t out_len);

/* If-None-Match vs formatted ETag (including quotes). */
int weed_etag_matches(const char *if_none_match, const char *etag);

int weed_path_has_extension(const char *path, size_t len);

uint32_t weed_load_u32_le(const unsigned char *p);
uint64_t weed_load_u64_le(const unsigned char *p);

#endif /* WEED_INDEX_H */
