#include "weed.h"
#include "weed_format.h"

#include <string.h>
#include <xxhash.h>

/*
 * Pack-time Cache-Control policy from MIME type.
 * Default (unknown): no-cache, max-age=0.
 */
void weed_cache_for_mime(const char *mime, uint8_t *flags_out, uint32_t *max_age_out)
{
	uint8_t flags = WEED_CACHE_NO_CACHE;
	uint32_t max_age = 0;

	if (mime) {
		if (strcmp(mime, "text/html") == 0) {
			flags = WEED_CACHE_NO_CACHE;
			max_age = 0;
		} else if (strcmp(mime, "text/css") == 0 ||
		           strcmp(mime, "text/javascript") == 0 ||
		           strcmp(mime, "application/javascript") == 0 ||
		           strcmp(mime, "application/json") == 0 ||
		           strcmp(mime, "application/wasm") == 0 ||
		           strcmp(mime, "image/svg+xml") == 0) {
			/* Stable URLs + firmware deploys: revalidate via ETag, no long TTL. */
			flags = (uint8_t)(WEED_CACHE_PUBLIC | WEED_CACHE_MUST_REVAL);
			max_age = 0;
		} else if (strncmp(mime, "image/", 6) == 0 ||
		           strncmp(mime, "font/", 5) == 0 ||
		           strcmp(mime, "application/font-woff") == 0 ||
		           strcmp(mime, "application/vnd.ms-fontobject") == 0) {
			flags = WEED_CACHE_PUBLIC;
			max_age = 604800u; /* 7 days */
		} else if (strncmp(mime, "audio/", 6) == 0 ||
		           strncmp(mime, "video/", 6) == 0) {
			flags = WEED_CACHE_PUBLIC;
			max_age = 86400u;
		}
		/* else keep default no-cache, max-age=0 */
	}

	*flags_out = flags;
	*max_age_out = max_age;
}

void weed_etag_xxh128(const void *data, size_t len, uint8_t out[WEED_ETAG_SIZE])
{
	XXH128_hash_t h = XXH3_128bits_withSeed(data, len, WEED_ETAG_SEED);
	/* LE low64 then high64 */
	uint64_t lo = h.low64;
	uint64_t hi = h.high64;
	for (int i = 0; i < 8; i++) {
		out[i] = (uint8_t)(lo >> (8 * i));
		out[8 + i] = (uint8_t)(hi >> (8 * i));
	}
}
