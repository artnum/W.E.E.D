#define _POSIX_C_SOURCE 200809L

#include "weed.h"
#include "weed_format.h"

#include <brotli/encode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

int weed_compress_gzip(const unsigned char *in, size_t in_len,
                       unsigned char **out, size_t *out_len)
{
	if (!in || !out || !out_len)
		return -1;

	/* gzip bound is slightly larger than deflateBound */
	uLong bound = compressBound((uLong)in_len) + 32;
	unsigned char *buf = (unsigned char *)malloc(bound);
	if (!buf)
		return -1;

	z_stream zs;
	memset(&zs, 0, sizeof zs);
	/* 15 window bits + 16 = gzip wrapper */
	if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
	                 Z_DEFAULT_STRATEGY) != Z_OK) {
		free(buf);
		return -1;
	}

	zs.next_in = (Bytef *)in;
	zs.avail_in = (uInt)in_len;
	zs.next_out = buf;
	zs.avail_out = (uInt)bound;

	int rc = deflate(&zs, Z_FINISH);
	if (rc != Z_STREAM_END) {
		deflateEnd(&zs);
		free(buf);
		return -1;
	}
	size_t n = (size_t)zs.total_out;
	deflateEnd(&zs);

	if (n >= in_len) {
		/* not smaller — caller skips twin */
		free(buf);
		return 1;
	}

	*out = buf;
	*out_len = n;
	return 0;
}

int weed_compress_br(const unsigned char *in, size_t in_len, unsigned char **out,
                     size_t *out_len)
{
	if (!in || !out || !out_len)
		return -1;

	size_t bound = BrotliEncoderMaxCompressedSize(in_len);
	if (bound == 0 && in_len > 0)
		return -1;
	if (bound == 0)
		bound = 1;

	unsigned char *buf = (unsigned char *)malloc(bound);
	if (!buf)
		return -1;

	size_t encoded = bound;
	/* quality 5: good ratio, still fast enough for deploy-time packing */
	if (!BrotliEncoderCompress(5, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC,
	                           in_len, in, &encoded, buf)) {
		free(buf);
		return -1;
	}

	if (encoded >= in_len) {
		free(buf);
		return 1;
	}

	*out = buf;
	*out_len = encoded;
	return 0;
}
