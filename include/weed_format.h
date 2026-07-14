#ifndef WEED_FORMAT_H
#define WEED_FORMAT_H

#include <stdint.h>

/* On-wire layout (little-endian):
 *
 *   u8  signature[WEED_SIG_SIZE]     RSA-4096 PKCS#1 v1.5 over SHA-256 of
 *                                    everything after this field
 *   u8  reserved[WEED_RESERVED_SIZE] first byte = format version (WEED_VERSION);
 *                                    remaining 15 bytes reserved (zeros)
 *   u64 file_count                   N
 *   u64 path_hash[N]                 xxh64(path), seed 0;
 *                                    sorted by (hash, path, encoding)
 *   u64 file_offset[N]               absolute offset of FILEITEM; same order
 *   FILEITEM...                      pack order; no padding
 *
 * FILEITEM:
 *   u64 content_len
 *   u32 path_len
 *   u32 mime_len
 *   u8  content_encoding             WEED_ENC_*
 *   u8  cache_flags                  WEED_CACHE_* bitfield
 *   u32 max_age                      seconds (with cache_flags → Cache-Control)
 *   u8  etag[WEED_ETAG_SIZE]         XXH3-128 of content, seed WEED_ETAG_SEED
 *   u8  path[path_len]
 *   u8  mime[mime_len]
 *   u8  content[content_len]
 *
 * Default cache when packer has no type rule: NO_CACHE, max_age=0.
 * Twins: same path, different encodings; each body has its own etag.
 */

#define WEED_SIG_SIZE       512u
#define WEED_RESERVED_SIZE  16u  /* 128 bits: [0]=version, [1..15] reserved */
#define WEED_VERSION        1u   /* on-wire format version (reserved[0]) */
#define WEED_XXH_SEED       0ull

/* Content ETag: XXH3 128-bit, seed 0xEB */
#define WEED_ETAG_SEED      0xEBull
#define WEED_ETAG_SIZE      16u

#define WEED_DEFAULT_ROOT_FILE "index.html"
#define WEED_DEFAULT_MIME      "text/plain"

#define WEED_ENC_IDENTITY  0u
#define WEED_ENC_GZIP      1u
#define WEED_ENC_BR        2u

#define WEED_COMPRESS_GZIP  1u
#define WEED_COMPRESS_BR    2u

/* cache_flags (u8 bitfield) → Cache-Control tokens */
#define WEED_CACHE_NO_CACHE   0x01u
#define WEED_CACHE_NO_STORE   0x02u
#define WEED_CACHE_PUBLIC     0x04u
#define WEED_CACHE_PRIVATE    0x08u
#define WEED_CACHE_IMMUTABLE  0x10u
#define WEED_CACHE_MUST_REVAL 0x20u

/* Fixed FILEITEM header size before path (all fields above path) */
#define WEED_ITEM_HDR_SIZE \
	(8u + 4u + 4u + 1u + 1u + 4u + WEED_ETAG_SIZE) /* 38 */

static inline uint64_t weed_header_size(uint64_t n)
{
	return (uint64_t)WEED_SIG_SIZE + (uint64_t)WEED_RESERVED_SIZE + 8ull
	       + 16ull * n;
}

static inline uint64_t weed_fileitem_size(uint32_t path_len, uint32_t mime_len,
                                         uint64_t content_len)
{
	return (uint64_t)WEED_ITEM_HDR_SIZE + (uint64_t)path_len +
	       (uint64_t)mime_len + content_len;
}

static inline const char *weed_enc_name(uint8_t enc)
{
	switch (enc) {
	case WEED_ENC_GZIP:
		return "gzip";
	case WEED_ENC_BR:
		return "br";
	default:
		return NULL;
	}
}

#endif /* WEED_FORMAT_H */
