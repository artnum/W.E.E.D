#define _POSIX_C_SOURCE 200809L

#include "weed.h"
#include "weed_format.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void openssl_err(const char *what)
{
	fprintf(stderr, "weed: %s\n", what);
	ERR_print_errors_fp(stderr);
}

int weed_sign_file(const char *pem_path, const char *weed_path)
{
	FILE *kf = fopen(pem_path, "rb");
	if (!kf) {
		perror(pem_path);
		return -1;
	}

	EVP_PKEY *pkey = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
	fclose(kf);
	if (!pkey) {
		openssl_err("failed to read private key");
		return -1;
	}

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
		fprintf(stderr, "weed: key is not RSA\n");
		EVP_PKEY_free(pkey);
		return -1;
	}

	int bits = EVP_PKEY_bits(pkey);
	if (bits != 4096) {
		fprintf(stderr, "weed: RSA key must be 4096 bits (got %d)\n", bits);
		EVP_PKEY_free(pkey);
		return -1;
	}

	FILE *f = fopen(weed_path, "rb+");
	if (!f) {
		perror(weed_path);
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (fseeko(f, (off_t)WEED_SIG_SIZE, SEEK_SET) != 0) {
		perror("fseeko");
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		openssl_err("EVP_MD_CTX_new");
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
		openssl_err("EVP_DigestSignInit");
		EVP_MD_CTX_free(mdctx);
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	unsigned char buf[64 * 1024];
	for (;;) {
		size_t n = fread(buf, 1, sizeof buf, f);
		if (n > 0) {
			if (EVP_DigestSignUpdate(mdctx, buf, n) != 1) {
				openssl_err("EVP_DigestSignUpdate");
				EVP_MD_CTX_free(mdctx);
				fclose(f);
				EVP_PKEY_free(pkey);
				return -1;
			}
		}
		if (n < sizeof buf) {
			if (ferror(f)) {
				perror("fread");
				EVP_MD_CTX_free(mdctx);
				fclose(f);
				EVP_PKEY_free(pkey);
				return -1;
			}
			break;
		}
	}

	size_t siglen = 0;
	if (EVP_DigestSignFinal(mdctx, NULL, &siglen) != 1) {
		openssl_err("EVP_DigestSignFinal (size)");
		EVP_MD_CTX_free(mdctx);
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (siglen != WEED_SIG_SIZE) {
		fprintf(stderr, "weed: unexpected signature length %zu (want %u)\n",
		        siglen, WEED_SIG_SIZE);
		EVP_MD_CTX_free(mdctx);
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	unsigned char *sig = (unsigned char *)malloc(siglen);
	if (!sig) {
		EVP_MD_CTX_free(mdctx);
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (EVP_DigestSignFinal(mdctx, sig, &siglen) != 1) {
		openssl_err("EVP_DigestSignFinal");
		free(sig);
		EVP_MD_CTX_free(mdctx);
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);

	if (fseeko(f, 0, SEEK_SET) != 0) {
		perror("fseeko");
		free(sig);
		fclose(f);
		return -1;
	}

	if (fwrite(sig, 1, WEED_SIG_SIZE, f) != WEED_SIG_SIZE) {
		perror("fwrite signature");
		free(sig);
		fclose(f);
		return -1;
	}

	free(sig);
	if (fclose(f) != 0) {
		perror("fclose");
		return -1;
	}
	return 0;
}
