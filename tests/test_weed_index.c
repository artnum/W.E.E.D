/*
 * Unit tests for pure mod_weed serve/index logic (weed_index + related).
 * Builds a real .weed with the packer, then exercises map parse, lookup,
 * Accept-Encoding, SPA extension rule, ETag/Cache-Control formatting.
 */

#define _POSIX_C_SOURCE 200809L

#include "weed.h"
#include "weed_format.h"
#include "weed_index.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail;

#define EXPECT(cond, msg)                                                      \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
			        (msg));                                        \
			g_fail++;                                              \
		}                                                              \
	} while (0)

#define EXPECT_EQ_I(a, b, msg)                                                 \
	do {                                                                   \
		long long _a = (long long)(a), _b = (long long)(b);            \
		if (_a != _b) {                                                \
			fprintf(stderr,                                        \
			        "FAIL %s:%d: %s (got %lld want %lld)\n",        \
			        __FILE__, __LINE__, (msg), _a, _b);            \
			g_fail++;                                              \
		}                                                              \
	} while (0)

static unsigned char *slurp(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return NULL;
	if (fseeko(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	off_t sz = ftello(f);
	if (sz < 0) {
		fclose(f);
		return NULL;
	}
	if (fseeko(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	unsigned char *buf = malloc((size_t)sz ? (size_t)sz : 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*out_len = (size_t)sz;
	return buf;
}

static void test_ae_wants(void)
{
	EXPECT(weed_ae_wants("gzip, deflate, br", "br") == 1, "br in list");
	EXPECT(weed_ae_wants("gzip, deflate, br", "gzip") == 1, "gzip in list");
	EXPECT(weed_ae_wants("gzip, deflate", "br") == 0, "br absent");
	EXPECT(weed_ae_wants(NULL, "br") == 0, "null ae");
	EXPECT(weed_ae_wants("br;q=0", "br") == 0, "br q=0");
	EXPECT(weed_ae_wants("br;q=0.0", "br") == 0, "br q=0.0");
	EXPECT(weed_ae_wants("br;q=1", "br") == 1, "br q=1");
	EXPECT(weed_ae_wants("gzip;q=0, br", "gzip") == 0, "gzip q=0");
	EXPECT(weed_ae_wants("gzip;q=0, br", "br") == 1, "br after gzip q=0");
}

static void test_path_ext_dotdot(void)
{
	EXPECT(weed_path_has_extension("css/app.css", 11) == 1, "css has ext");
	EXPECT(weed_path_has_extension("settings", 8) == 0, "settings no ext");
	EXPECT(weed_path_has_extension("a/b/c", 5) == 0, "nested no ext");
	EXPECT(weed_path_has_extension("a/b/c.js", 8) == 1, "nested has ext");
	EXPECT(weed_path_has_extension("", 0) == 0, "empty");

	EXPECT(weed_has_dotdot("../x", 4) == 1, "../x");
	EXPECT(weed_has_dotdot("a/../b", 6) == 1, "a/../b");
	EXPECT(weed_has_dotdot("a/b", 3) == 0, "a/b ok");
	EXPECT(weed_has_dotdot("..", 2) == 1, ".. alone");
}

static void test_etag_cache_format(void)
{
	uint8_t et[WEED_ETAG_SIZE];
	memset(et, 0, sizeof et);
	et[0] = 0xab;
	et[15] = 0xcd;
	char buf[35];
	weed_format_etag(et, buf);
	EXPECT(buf[0] == '"' && buf[33] == '"' && buf[34] == '\0', "etag quotes");
	EXPECT(strncmp(buf, "\"ab", 3) == 0, "etag starts ab");
	EXPECT(strstr(buf, "cd\"") != NULL, "etag ends cd");

	EXPECT(weed_etag_matches(buf, buf) == 1, "exact match");
	EXPECT(weed_etag_matches("*", buf) == 1, "star");
	EXPECT(weed_etag_matches("\"other\"", buf) == 0, "mismatch");
	EXPECT(weed_etag_matches("W/\"ab0000000000000000000000000000cd\"", buf) ==
	           1,
	       "weak prefix ignored for compare form");
	/* W/ then same tag body — our matcher strips W/ then compares */
	char weak[40];
	snprintf(weak, sizeof weak, "W/%s", buf);
	EXPECT(weed_etag_matches(weak, buf) == 1, "W/ prefix");

	char cc[128];
	weed_format_cache_control(WEED_CACHE_NO_CACHE, 0, cc, sizeof cc);
	EXPECT(strstr(cc, "no-cache") != NULL, "no-cache present");
	EXPECT(strstr(cc, "max-age=0") != NULL, "max-age=0");

	weed_format_cache_control(
	    (uint8_t)(WEED_CACHE_PUBLIC | WEED_CACHE_MUST_REVAL), 0, cc,
	    sizeof cc);
	EXPECT(strstr(cc, "public") != NULL, "public");
	EXPECT(strstr(cc, "must-revalidate") != NULL, "must-revalidate");
}

static void test_archive_lookup(const char *weed_path, const char *pub_path)
{
	EXPECT(weed_verify_file(pub_path, weed_path) == 0, "verify archive");

	size_t len = 0;
	unsigned char *buf = slurp(weed_path, &len);
	EXPECT(buf != NULL, "slurp archive");
	if (!buf)
		return;

	weed_map map;
	EXPECT(weed_map_from_buffer(buf, (uint64_t)len, &map) == 0, "map open");
	EXPECT(map.n >= 2, "at least root + one asset");

	/* Corrupt version */
	{
		unsigned char *copy = malloc(len);
		memcpy(copy, buf, len);
		uint64_t n = weed_load_u64_le(copy + len - 8);
		uint64_t hs = len - weed_header_size(n);
		copy[hs + 16 * n] = 99; /* reserved[0] */
		weed_map bad;
		EXPECT(weed_map_from_buffer(copy, (uint64_t)len, &bad) != 0,
		       "bad version rejected");
		free(copy);
	}

	weed_hit hit;
	int64_t idx;

	/* Root "" */
	idx = weed_lookup(&map, "", 0, 0, 0, &hit);
	EXPECT(idx >= 0, "root found");
	EXPECT(hit.enc == WEED_ENC_IDENTITY, "root identity");
	EXPECT(hit.clen > 0, "root has body");
	EXPECT(hit.cache_flags & WEED_CACHE_NO_CACHE, "root no-cache");

	/* Prefer br when available */
	idx = weed_lookup(&map, "css/app.css", strlen("css/app.css"), 1, 1, &hit);
	EXPECT(idx >= 0, "css found with br want");
	if (idx >= 0) {
		/* smoke packs with --compress; twin may exist */
		if (hit.enc == WEED_ENC_BR) {
			EXPECT(weed_enc_name(hit.enc) &&
			           strcmp(weed_enc_name(hit.enc), "br") == 0,
			       "content-encoding br");
		}
		EXPECT(hit.mlen > 0 && hit.mime[0] == 't', "css mime text/...");
	}

	/* Identity when client wants nothing */
	idx = weed_lookup(&map, "css/app.css", strlen("css/app.css"), 0, 0, &hit);
	EXPECT(idx >= 0 && hit.enc == WEED_ENC_IDENTITY, "css identity without AE");

	/* Missing path */
	idx = weed_lookup(&map, "nope.xyz", strlen("nope.xyz"), 1, 1, &hit);
	EXPECT(idx < 0, "missing path");

	/* SPA rule: extension vs not (logic only — handler uses this) */
	EXPECT(weed_path_has_extension("settings", 8) == 0, "spa candidate");
	EXPECT(weed_path_has_extension("missing.js", 10) == 1, "asset no spa");

	/* SPA fallback simulation */
	idx = weed_lookup(&map, "settings", strlen("settings"), 0, 0, &hit);
	if (idx < 0 && !weed_path_has_extension("settings", 8)) {
		idx = weed_lookup(&map, "", 0, 0, 0, &hit);
		EXPECT(idx >= 0, "spa fallback to root");
	}

	/* Body bytes at content_off match length and stay inside map */
	idx = weed_lookup(&map, "", 0, 0, 0, &hit);
	if (idx >= 0) {
		EXPECT(hit.content_off + hit.clen <= map.header_start,
		       "body inside payload");
		EXPECT(hit.content_off >= WEED_SIG_SIZE, "body after sig");
	}

	free(buf);
}

static void test_le_helpers(void)
{
	unsigned char b[8] = {0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00};
	EXPECT_EQ_I(weed_load_u32_le(b), 0x12345678, "u32 le");
	EXPECT_EQ_I(weed_load_u64_le(b), 0x12345678, "u64 le low");
}

int main(void)
{
	const char *key = "build/test_key.pem";
	const char *pub = "build/test_pub.pem";
	const char *weed = "build/test_unit.weed";
	const char *root = "build/test_unit_root";

	/* Ensure keys + sample tree */
	if (access(key, R_OK) != 0 || access(pub, R_OK) != 0) {
		fprintf(stderr, "need %s and %s (make test-key)\n", key, pub);
		return 2;
	}

	system("rm -rf build/test_unit_root && mkdir -p build/test_unit_root/css");
	system("python3 -c \"print('<html>'+'ok'*500+'</html>')\" > "
	       "build/test_unit_root/index.html");
	system("python3 -c \"print('body{x:1;}'*200)\" > "
	       "build/test_unit_root/css/app.css");

	char cmd[512];
	snprintf(cmd, sizeof cmd,
	         "./build/weed pack -o %s -k %s --compress br,gzip %s >/dev/null",
	         weed, key, root);
	if (system(cmd) != 0) {
		fprintf(stderr, "pack failed\n");
		return 2;
	}

	test_le_helpers();
	test_ae_wants();
	test_path_ext_dotdot();
	test_etag_cache_format();
	test_archive_lookup(weed, pub);

	if (g_fail) {
		fprintf(stderr, "\n%d test failure(s)\n", g_fail);
		return 1;
	}
	fprintf(stderr, "test_weed_index: all ok\n");
	return 0;
}
