#include "weed.h"
#include "weed_format.h"

#include <string.h>

struct mime_ent {
	const char *ext;
	const char *mime;
};

/* Common web static assets; default is WEED_DEFAULT_MIME. */
static const struct mime_ent mime_table[] = {
    {"html", "text/html"},
    {"htm", "text/html"},
    {"css", "text/css"},
    {"js", "text/javascript"},
    {"mjs", "text/javascript"},
    {"json", "application/json"},
    {"map", "application/json"},
    {"txt", "text/plain"},
    {"xml", "application/xml"},
    {"svg", "image/svg+xml"},
    {"png", "image/png"},
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"gif", "image/gif"},
    {"webp", "image/webp"},
    {"ico", "image/x-icon"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},
    {"ttf", "font/ttf"},
    {"otf", "font/otf"},
    {"eot", "application/vnd.ms-fontobject"},
    {"wasm", "application/wasm"},
    {"pdf", "application/pdf"},
    {"mp4", "video/mp4"},
    {"webm", "video/webm"},
    {"mp3", "audio/mpeg"},
    {"ogg", "audio/ogg"},
    {"wav", "audio/wav"},
    {"zip", "application/zip"},
    {"gz", "application/gzip"},
    {"webmanifest", "application/manifest+json"},
    {NULL, NULL},
};

const char *weed_mime_from_path(const char *path, size_t path_len)
{
	if (!path || path_len == 0)
		return WEED_DEFAULT_MIME;

	/* Find last '.' after last '/' */
	const char *base = path;
	for (size_t i = 0; i < path_len; i++) {
		if (path[i] == '/')
			base = path + i + 1;
	}

	const char *dot = NULL;
	size_t base_len = (size_t)(path + path_len - base);
	for (size_t i = 0; i < base_len; i++) {
		if (base[i] == '.')
			dot = base + i;
	}
	if (!dot || dot == base || dot + 1 >= path + path_len)
		return WEED_DEFAULT_MIME;

	const char *ext = dot + 1;
	size_t ext_len = (size_t)(path + path_len - ext);

	/* Case-insensitive extension match (ASCII). */
	for (const struct mime_ent *e = mime_table; e->ext; e++) {
		size_t n = strlen(e->ext);
		if (n != ext_len)
			continue;
		int match = 1;
		for (size_t i = 0; i < n; i++) {
			char a = ext[i];
			char b = e->ext[i];
			if (a >= 'A' && a <= 'Z')
				a = (char)(a - 'A' + 'a');
			if (a != b) {
				match = 0;
				break;
			}
		}
		if (match)
			return e->mime;
	}
	return WEED_DEFAULT_MIME;
}
