CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -std=c11
CPPFLAGS += -Iinclude
LDFLAGS ?=
LDLIBS  ?=

APXS    ?= apxs2

# xxHash (system); OpenSSL libcrypto; ICU for UTF-8 NFC
XXHASH_CFLAGS := $(shell pkg-config --cflags libxxhash 2>/dev/null)
XXHASH_LIBS   := $(shell pkg-config --libs libxxhash 2>/dev/null)
ifeq ($(XXHASH_LIBS),)
  XXHASH_LIBS := -lxxhash
endif

CRYPTO_LIBS := $(shell pkg-config --libs libcrypto 2>/dev/null)
ifeq ($(CRYPTO_LIBS),)
  CRYPTO_LIBS := -lcrypto
endif

ICU_CFLAGS := $(shell pkg-config --cflags icu-uc 2>/dev/null)
ICU_LIBS   := $(shell pkg-config --libs icu-uc 2>/dev/null)
ifeq ($(ICU_LIBS),)
  ICU_LIBS := -licuuc -licudata
endif

BROTLI_CFLAGS := $(shell pkg-config --cflags libbrotlienc 2>/dev/null)
BROTLI_LIBS   := $(shell pkg-config --libs libbrotlienc 2>/dev/null)
ifeq ($(BROTLI_LIBS),)
  BROTLI_LIBS := -lbrotlienc
endif

ZLIB_LIBS := $(shell pkg-config --libs zlib 2>/dev/null)
ifeq ($(ZLIB_LIBS),)
  ZLIB_LIBS := -lz
endif

CPPFLAGS += $(XXHASH_CFLAGS) $(ICU_CFLAGS) $(BROTLI_CFLAGS)
LDLIBS   += $(XXHASH_LIBS) $(CRYPTO_LIBS) $(ICU_LIBS) $(BROTLI_LIBS) $(ZLIB_LIBS)

PACK_SRCS := src/main.c src/pack.c src/path.c src/mime.c src/sign.c src/verify.c \
             src/compress.c src/cache_policy.c
PACK_OBJS := $(PACK_SRCS:src/%.c=build/%.o)

MOD_SRCS := mod/mod_weed.c src/path.c src/verify.c

.PHONY: all module clean test-key smoke smoke-apache install-module

all: build/weed module

build/weed: $(PACK_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c include/weed.h include/weed_format.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

# Apache module via apxs (outputs build/mod_weed.so)
module: build/mod_weed.so

build/mod_weed.so: $(MOD_SRCS) include/weed.h include/weed_format.h | build
	$(APXS) -c \
		-o mod_weed.so \
		-I$(CURDIR)/include \
		$(XXHASH_CFLAGS) $(ICU_CFLAGS) \
		-Wc,-Wall -Wc,-O2 \
		$(MOD_SRCS) \
		$(XXHASH_LIBS) $(CRYPTO_LIBS) $(ICU_LIBS)
	@# apxs drops the .so next to the first source or in .libs/
	@if [ -f mod/.libs/mod_weed.so ]; then cp -f mod/.libs/mod_weed.so build/mod_weed.so; \
	elif [ -f .libs/mod_weed.so ]; then cp -f .libs/mod_weed.so build/mod_weed.so; \
	elif [ -f mod_weed.so ]; then cp -f mod_weed.so build/mod_weed.so; \
	else ls -la mod/.libs .libs 2>/dev/null; exit 1; fi
	@echo "built $@"

install-module: build/mod_weed.so
	$(APXS) -i -n weed build/mod_weed.so

clean:
	rm -rf build .libs mod/.libs *.lo *.slo *.la mod/*.lo mod/*.slo mod/*.la
	rm -f mod_weed.so mod_weed.la mod_weed.lo

# Dev helpers
test-key: build/test_key.pem build/test_pub.pem

build/test_key.pem: | build
	openssl genrsa -out $@ 4096 2>/dev/null

build/test_pub.pem: build/test_key.pem
	openssl rsa -in build/test_key.pem -pubout -out $@ 2>/dev/null

smoke: all test-key
	rm -rf build/smoke_root build/site.weed build/site_list.weed
	mkdir -p build/smoke_root/css
	@# large enough that br/gzip twins beat identity size
	python3 -c "print('<html>'+'ok'*2000+'</html>')" > build/smoke_root/index.html
	python3 -c "print('body{margin:0;}'*500)" > build/smoke_root/css/app.css
	ln -sf ../index.html build/smoke_root/css/link.html
	./build/weed pack -o build/site.weed -k build/test_key.pem \
	  --compress br,gzip build/smoke_root
	@echo "archive size: $$(wc -c < build/site.weed) bytes"
	@# stdin file list (+ optional -C)
	printf '%s\n' 'index.html' 'css/app.css' \
	  | ./build/weed pack -o build/site_list.weed -k build/test_key.pem \
	      -C build/smoke_root -
	@echo "list-archive size: $$(wc -c < build/site_list.weed) bytes"
	./build/weed 2>/dev/null || true

# Local Apache smoke (single-process -X, port 18080, current user)
smoke-apache: smoke module
	@ROOT="$(CURDIR)"; LOG="$$ROOT/build/apache-smoke"; \
	mkdir -p "$$LOG"; \
	U=$$(id -un); G=$$(id -gn); \
	printf '%s\n' \
	  'ServerName localhost' \
	  'Listen 127.0.0.1:18080' \
	  "PidFile $$LOG/httpd.pid" \
	  "ErrorLog $$LOG/error.log" \
	  'LogLevel info' \
	  'ServerRoot /usr/lib/apache2' \
	  "DocumentRoot $$LOG" \
	  'LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so' \
	  'LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so' \
	  "LoadModule weed_module $$ROOT/build/mod_weed.so" \
	  "User $$U" \
	  "Group $$G" \
	  "<Directory $$LOG>" \
	  '  Require all denied' \
	  '</Directory>' \
	  '<Location />' \
	  '  Require all granted' \
	  '  SetHandler weed' \
	  "  WeedArchive $$ROOT/build/site.weed" \
	  "  WeedPublicKey $$ROOT/build/test_pub.pem" \
	  '  WeedSpa On' \
	  '</Location>' \
	  > "$$LOG/httpd.conf"; \
	rm -f "$$LOG/httpd.pid" "$$LOG/body_root.html" "$$LOG/body.css" "$$LOG/body_spa.html"; \
	fuser -k 18080/tcp >/dev/null 2>&1 || true; \
	sleep 0.2; \
	/usr/sbin/apache2 -f "$$LOG/httpd.conf" -C "DefaultRuntimeDir $$LOG" -X & \
	APID=$$!; \
	ok=0; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
	  kill -0 $$APID 2>/dev/null || break; \
	  if curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:18080/" 2>/dev/null | grep -q 200; then ok=1; break; fi; \
	  sleep 0.15; \
	done; \
	if [ "$$ok" != 1 ]; then \
	  echo "apache failed to start:"; cat "$$LOG/error.log" 2>/dev/null; kill $$APID 2>/dev/null; exit 1; \
	fi; \
	echo "=== GET / ==="; \
	curl -sS -D "$$LOG/hdr.root" "http://127.0.0.1:18080/" -o "$$LOG/body_root.html"; \
	head -20 "$$LOG/hdr.root"; \
	ETAG=$$(awk 'BEGIN{IGNORECASE=1} /^ETag:/{gsub(/\r/,""); sub(/^ETag:[[:space:]]*/,""); print; exit}' "$$LOG/hdr.root"); \
	echo "=== GET / If-None-Match (expect 304) ==="; \
	curl -sS -o /dev/null -w "status=%{http_code}\n" -H "If-None-Match: $$ETAG" "http://127.0.0.1:18080/"; \
	echo "=== GET /css/app.css (identity) ==="; \
	curl -sS -D "$$LOG/hdr.css" "http://127.0.0.1:18080/css/app.css" -o "$$LOG/body.css" | head -5; \
	echo "=== GET /css/app.css Accept-Encoding: br ==="; \
	curl -sS -D "$$LOG/hdr.css.br" -H 'Accept-Encoding: br' \
	  "http://127.0.0.1:18080/css/app.css" -o "$$LOG/body.css.br" | head -5; \
	echo "=== GET /settings (SPA fallback) ==="; \
	curl -sS -D - "http://127.0.0.1:18080/settings" -o "$$LOG/body_spa.html" | head -20; \
	echo "=== GET /missing.js (asset, no fallback) ==="; \
	MISS=$$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:18080/missing.js"); \
	echo "status=$$MISS"; \
	kill $$APID 2>/dev/null; wait $$APID 2>/dev/null; \
	echo "body_root: $$(cat $$LOG/body_root.html)"; \
	echo "body_css: $$(cat $$LOG/body.css)"; \
	echo "body_spa: $$(cat $$LOG/body_spa.html)"; \
	grep -q 'mmap' "$$LOG/error.log" && \
	  grep -qi 'etag:' "$$LOG/hdr.root" && \
	  grep -qi 'cache-control:.*no-cache' "$$LOG/hdr.root" && \
	  grep -qi 'last-modified:' "$$LOG/hdr.root" && \
	  grep -q 'ok' "$$LOG/body_root.html" && grep -q 'body' "$$LOG/body.css" && \
	  grep -q 'ok' "$$LOG/body_spa.html" && [ "$$MISS" = "404" ] && \
	  grep -qi 'content-encoding: *br' "$$LOG/hdr.css.br" && \
	  test -s "$$LOG/body.css.br" && ! cmp -s "$$LOG/body.css" "$$LOG/body.css.br" && \
	  echo "smoke-apache: OK"
