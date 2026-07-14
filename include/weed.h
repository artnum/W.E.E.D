#ifndef WEED_H
#define WEED_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* path.c */
int weed_path_nfc(const char *in, size_t in_len, char **out, size_t *out_len);
/* Relative path from root: strip leading "./" and '/', normalize NFC.
 * Returns 0 on success; *out is malloc'd. */
int weed_relpath_nfc(const char *root, const char *abspath, char **out,
                     size_t *out_len);

/* mime.c */
const char *weed_mime_from_path(const char *path, size_t path_len);

/* cache_policy.c — pack-time Cache-Control + ETag */
void weed_cache_for_mime(const char *mime, uint8_t *flags_out, uint32_t *max_age_out);
void weed_etag_xxh128(const void *data, size_t len, uint8_t out[16]);

/* sign.c — RSA-4096 PKCS#1 v1.5 + SHA-256; sig must be WEED_SIG_SIZE bytes. */
int weed_sign_file(const char *pem_path, const char *weed_path);

/* verify.c — same scheme; pem_pub_path is a SubjectPublicKeyInfo PEM. */
int weed_verify_file(const char *pem_pub_path, const char *weed_path);

/* compress.c — return 0 ok (out malloc'd), 1 skip (not smaller), -1 error */
int weed_compress_gzip(const unsigned char *in, size_t in_len,
                       unsigned char **out, size_t *out_len);
int weed_compress_br(const unsigned char *in, size_t in_len, unsigned char **out,
                     size_t *out_len);

/* pack.c — compress_flags: WEED_COMPRESS_GZIP | WEED_COMPRESS_BR */
int weed_pack(const char *root_dir, const char *out_path, const char *key_path,
              const char *root_file, unsigned compress_flags);

/*
 * Pack paths listed on `in`, one path per line (empty lines skipped).
 * Paths are inventoried first (strings only); each file is then streamed to
 * the archive immediately so compressed bodies are not retained in RAM;
 * the little-endian header (catalog) is written at EOF.
 * Archive path = NFC-normalized line (no leading '/').
 * Disk path = line, or base_dir/line when base_dir is non-NULL/non-empty.
 */
int weed_pack_list(FILE *in, const char *base_dir, const char *out_path,
                   const char *key_path, const char *root_file,
                   unsigned compress_flags);

#endif /* WEED_H */
