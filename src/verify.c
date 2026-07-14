#define _POSIX_C_SOURCE 200809L

#include "weed.h"
#include "weed_format.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>

static void openssl_err(const char *what)
{
	fprintf(stderr, "weed: %s\n", what);
	ERR_print_errors_fp(stderr);
}

int weed_verify_file(const char *pem_pub_path, const char *weed_path)
{
	FILE *kf = fopen(pem_pub_path, "rb");
	if (!kf) {
		perror(pem_pub_path);
		return -1;
	}

	EVP_PKEY *pkey = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
	fclose(kf);
	if (!pkey) {
		openssl_err("failed to read public key (expect SubjectPublicKeyInfo PEM)");
		return -1;
	}

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
		fprintf(stderr, "weed: public key is not RSA\n");
		EVP_PKEY_free(pkey);
		return -1;
	}

	int bits = EVP_PKEY_bits(pkey);
	if (bits != 4096) {
		fprintf(stderr, "weed: RSA key must be 4096 bits (got %d)\n", bits);
		EVP_PKEY_free(pkey);
		return -1;
	}

	FILE *f = fopen(weed_path, "rb");
	if (!f) {
		perror(weed_path);
		EVP_PKEY_free(pkey);
		return -1;
	}

	unsigned char sig[WEED_SIG_SIZE];
	if (fread(sig, 1, WEED_SIG_SIZE, f) != WEED_SIG_SIZE) {
		fprintf(stderr, "weed: short read (signature) in %s\n", weed_path);
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

	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
		openssl_err("EVP_DigestVerifyInit");
		EVP_MD_CTX_free(mdctx);
		fclose(f);
		EVP_PKEY_free(pkey);
		return -1;
	}

	unsigned char buf[64 * 1024];
	for (;;) {
		size_t n = fread(buf, 1, sizeof buf, f);
		if (n > 0) {
			if (EVP_DigestVerifyUpdate(mdctx, buf, n) != 1) {
				openssl_err("EVP_DigestVerifyUpdate");
				EVP_MD_CTX_free(mdctx);
				fclose(f);
				EVP_PKEY_free(pkey);
				return -1;
			}
		}
		if (n < sizeof buf) {
			if (ferror(f)) {
				perror(weed_path);
				EVP_MD_CTX_free(mdctx);
				fclose(f);
				EVP_PKEY_free(pkey);
				return -1;
			}
			break;
		}
	}
	fclose(f);

	int rc = EVP_DigestVerifyFinal(mdctx, sig, WEED_SIG_SIZE);
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);

	if (rc != 1) {
		if (rc == 0)
			fprintf(stderr, "weed: signature verification failed: %s\n",
			        weed_path);
		else
			openssl_err("EVP_DigestVerifyFinal");
		return -1;
	}
	return 0;
}
