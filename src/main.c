#define _POSIX_C_SOURCE 200809L

#include "weed.h"
#include "weed_format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
	fprintf(stderr,
	        "Usage:\n"
	        "  %s pack -o <out.weed> -k <priv.pem> [-r <root-file>]\n"
	        "          [--compress br,gzip] <root_dir>\n"
	        "  %s pack -o <out.weed> -k <priv.pem> [-r <root-file>] [-C <dir>]\n"
	        "          [--compress br,gzip] -\n"
	        "\n"
	        "  Pack files into a signed Weed archive\n"
	        "  (Whole-site Enclosed Exportable Disk-image).\n"
	        "\n"
	        "  <root_dir>  recursively pack a directory\n"
	        "  -           read file paths from stdin, one per line\n"
	        "\n"
	        "  -o   output path (required)\n"
	        "  -k   RSA-4096 private key PEM (required)\n"
	        "  -r   root document name (default: %s) → archive path \"\"\n"
	        "  -C   base directory for stdin list paths\n"
	        "  --compress br,gzip|br|gzip\n"
	        "       store smaller brotli/gzip twins alongside identity\n"
	        "\n"
	        "Examples:\n"
	        "  %s pack -o site.weed -k key.pem --compress br,gzip ./dist\n"
	        "  git ls-files | %s pack -o site.weed -k key.pem --compress br -\n",
	        argv0, argv0, WEED_DEFAULT_ROOT_FILE, argv0, argv0);
}

static int parse_compress(const char *arg, unsigned *flags)
{
	*flags = 0;
	char *buf = strdup(arg);
	if (!buf)
		return -1;
	char *save = NULL;
	for (char *tok = strtok_r(buf, ",+", &save); tok;
	     tok = strtok_r(NULL, ",+", &save)) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (strcmp(tok, "br") == 0 || strcmp(tok, "brotli") == 0)
			*flags |= WEED_COMPRESS_BR;
		else if (strcmp(tok, "gzip") == 0 || strcmp(tok, "gz") == 0)
			*flags |= WEED_COMPRESS_GZIP;
		else {
			fprintf(stderr, "weed: unknown compress type \"%s\"\n", tok);
			free(buf);
			return -1;
		}
	}
	free(buf);
	if (*flags == 0) {
		fprintf(stderr, "weed: --compress needs br and/or gzip\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}

	if (strcmp(argv[1], "pack") != 0) {
		fprintf(stderr, "weed: unknown command \"%s\"\n", argv[1]);
		usage(argv[0]);
		return 2;
	}

	const char *out_path = NULL;
	const char *key_path = NULL;
	const char *root_file = WEED_DEFAULT_ROOT_FILE;
	const char *base_dir = NULL;
	const char *source = NULL;
	int from_stdin = 0;
	unsigned compress_flags = 0;

	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-o") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "weed: -o needs an argument\n");
				return 2;
			}
			out_path = argv[i];
		} else if (strcmp(argv[i], "-k") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "weed: -k needs an argument\n");
				return 2;
			}
			key_path = argv[i];
		} else if (strcmp(argv[i], "-r") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "weed: -r needs an argument\n");
				return 2;
			}
			root_file = argv[i];
		} else if (strcmp(argv[i], "-C") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "weed: -C needs an argument\n");
				return 2;
			}
			base_dir = argv[i];
		} else if (strcmp(argv[i], "--compress") == 0 ||
		           strcmp(argv[i], "-z") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "weed: --compress needs an argument\n");
				return 2;
			}
			if (parse_compress(argv[i], &compress_flags) != 0)
				return 2;
		} else if (strcmp(argv[i], "-h") == 0 ||
		           strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else if (strcmp(argv[i], "-") == 0) {
			if (source) {
				fprintf(stderr, "weed: unexpected argument %s\n", argv[i]);
				return 2;
			}
			source = "-";
			from_stdin = 1;
		} else if (argv[i][0] == '-') {
			fprintf(stderr, "weed: unknown option %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		} else if (!source) {
			source = argv[i];
		} else {
			fprintf(stderr, "weed: unexpected argument %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		}
	}

	if (!out_path || !key_path || !source) {
		fprintf(stderr,
		        "weed: pack requires -o, -k, and <root_dir> or -\n");
		usage(argv[0]);
		return 2;
	}

	if (from_stdin) {
		if (weed_pack_list(stdin, base_dir, out_path, key_path, root_file,
		                   compress_flags) != 0)
			return 1;
	} else {
		if (base_dir) {
			fprintf(stderr, "weed: -C is only valid with stdin list (-)\n");
			return 2;
		}
		if (weed_pack(source, out_path, key_path, root_file, compress_flags) !=
		    0)
			return 1;
	}
	return 0;
}
