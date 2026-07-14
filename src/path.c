#include "weed.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>

int weed_path_nfc(const char *in, size_t in_len, char **out, size_t *out_len)
{
	UErrorCode err = U_ZERO_ERROR;
	const UNormalizer2 *nfc = unorm2_getNFCInstance(&err);
	if (U_FAILURE(err) || !nfc) {
		fprintf(stderr, "weed: ICU NFC unavailable: %s\n", u_errorName(err));
		return -1;
	}

	/* UTF-8 -> UTF-16 */
	int32_t u16_cap = (int32_t)in_len + 1;
	UChar *u16 = (UChar *)malloc((size_t)u16_cap * sizeof(UChar));
	if (!u16)
		return -1;

	int32_t u16_len = 0;
	u_strFromUTF8(u16, u16_cap, &u16_len, in, (int32_t)in_len, &err);
	if (err == U_BUFFER_OVERFLOW_ERROR) {
		free(u16);
		u16_cap = u16_len + 1;
		u16 = (UChar *)malloc((size_t)u16_cap * sizeof(UChar));
		if (!u16)
			return -1;
		err = U_ZERO_ERROR;
		u_strFromUTF8(u16, u16_cap, &u16_len, in, (int32_t)in_len, &err);
	}
	if (U_FAILURE(err)) {
		fprintf(stderr, "weed: invalid UTF-8 path: %s\n", u_errorName(err));
		free(u16);
		return -1;
	}

	int32_t nfc_cap = u16_len * 2 + 16;
	UChar *nfc_buf = (UChar *)malloc((size_t)nfc_cap * sizeof(UChar));
	if (!nfc_buf) {
		free(u16);
		return -1;
	}

	err = U_ZERO_ERROR;
	int32_t nfc_len =
	    unorm2_normalize(nfc, u16, u16_len, nfc_buf, nfc_cap, &err);
	if (err == U_BUFFER_OVERFLOW_ERROR) {
		free(nfc_buf);
		nfc_cap = nfc_len + 1;
		nfc_buf = (UChar *)malloc((size_t)nfc_cap * sizeof(UChar));
		if (!nfc_buf) {
			free(u16);
			return -1;
		}
		err = U_ZERO_ERROR;
		nfc_len = unorm2_normalize(nfc, u16, u16_len, nfc_buf, nfc_cap, &err);
	}
	free(u16);
	if (U_FAILURE(err)) {
		fprintf(stderr, "weed: NFC normalize failed: %s\n", u_errorName(err));
		free(nfc_buf);
		return -1;
	}

	/* UTF-16 -> UTF-8 */
	int32_t u8_cap = nfc_len * 3 + 1;
	char *u8 = (char *)malloc((size_t)u8_cap);
	if (!u8) {
		free(nfc_buf);
		return -1;
	}

	err = U_ZERO_ERROR;
	int32_t u8_len = 0;
	u_strToUTF8(u8, u8_cap, &u8_len, nfc_buf, nfc_len, &err);
	if (err == U_BUFFER_OVERFLOW_ERROR) {
		free(u8);
		u8_cap = u8_len + 1;
		u8 = (char *)malloc((size_t)u8_cap);
		if (!u8) {
			free(nfc_buf);
			return -1;
		}
		err = U_ZERO_ERROR;
		u_strToUTF8(u8, u8_cap, &u8_len, nfc_buf, nfc_len, &err);
	}
	free(nfc_buf);
	if (U_FAILURE(err)) {
		fprintf(stderr, "weed: UTF-8 encode failed: %s\n", u_errorName(err));
		free(u8);
		return -1;
	}

	*out = u8;
	*out_len = (size_t)u8_len;
	return 0;
}

int weed_relpath_nfc(const char *root, const char *abspath, char **out,
                     size_t *out_len)
{
	size_t root_len = strlen(root);
	/* Allow root with or without trailing slash */
	while (root_len > 0 && root[root_len - 1] == '/')
		root_len--;

	if (strncmp(abspath, root, root_len) != 0) {
		fprintf(stderr, "weed: path not under root: %s\n", abspath);
		return -1;
	}

	const char *rel = abspath + root_len;
	while (*rel == '/')
		rel++;

	/* Collapse leading "./" */
	while (rel[0] == '.' && rel[1] == '/')
		rel += 2;

	/* No ".." segments for safety */
	if (strstr(rel, "/../") || strncmp(rel, "../", 3) == 0 ||
	    strcmp(rel, "..") == 0) {
		fprintf(stderr, "weed: refusing path with '..': %s\n", rel);
		return -1;
	}

	return weed_path_nfc(rel, strlen(rel), out, out_len);
}
