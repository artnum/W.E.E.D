# Weed

**Weed** packs a static website into a single signed archive (`.weed`) and serves it from Apache **without unpacking**. Think firmware for frontends: one file on every server, verified on load, mmap’d for serving.

Format version: **1** (`reserved[0] = 1`).

### Written By

This idea has been around in my head for quite a long time now, I never got the time to write it. So
I tasked Grok to do what I was too lazy to do. I didn't do any extensive code-review myself, I just
needed the idea to come out in some way.
The idea is really to have something were you put all your html/js/css file in their final shipable
form send it to the server as on blob, change a symlink, reload apache and done. If the new image is
missing something, just switch back to the old one. The idea is the atomicity of the operation.
And maybe someone may change the apache module to support A/B testing in some kind of automated way,
put two W.E.E.D image that are distributed at random between session (it is not supported yet).
It can be used as a solution for dynamic generated static web site : on process during the night
generate the whole website, pack it into W.E.E.D, replace the previous version, reload apache and
done, no tiny forgotten file left by accident that may popup six months down the road to make suffer
in pain trying to figure out what's wrong.
So this section is, at this time, the only human written part. The rest is all Grok.

### Name

**W.E.E.D.** — **W**hole-site **E**nclosed **E**xportable **D**isk-image.

Over-serious on purpose: the entire static site is sealed into one **enclosed**, **exportable** artifact—closer to a **disk image** than a tarball of loose paths. You ship the image, verify it, mmap it, and serve; you do not sprinkle files across the document root.

(File extension: `.weed`.)

---

## What you get

| Component | Role |
|-----------|------|
| `weed` CLI | Pack + RSA-4096 sign |
| `mod_weed` | Apache module: verify, mmap, serve |

**Deploy model:** build → pack → copy `site.weed` + public key to servers → reload Apache. No rsync of thousands of files.

**Packer memory:** path inventory only, then one file at a time (stream identity; optional compress buffer for that file only); catalog metadata for the little-endian header at EOF.

---

## Dependencies

### Build host / CI (packer + module)

Debian/Ubuntu example:

```bash
sudo apt-get install -y \
  build-essential pkg-config \
  libssl-dev libxxhash-dev libicu-dev \
  libbrotli-dev zlib1g-dev \
  apache2-dev
```

- **OpenSSL** — sign / verify (RSA-4096)
- **xxHash** — path index (64) + content ETag (128)
- **ICU** — UTF-8 NFC paths
- **Brotli + zlib** — optional compressed twins at pack time
- **apache2-dev / apxs** — module only

### Server (runtime)

- Apache 2.4
- Same shared libraries: `libcrypto`, `libxxhash`, `libicuuc`, plus module deps as linked

---

## Build

```bash
git clone <this-repo> web-distribution
cd web-distribution
make          # build/weed + build/mod_weed.so
# optional local checks:
make smoke
make smoke-apache
```

Install the module system-wide (needs root):

```bash
sudo make install-module
# installs via apxs, typically under /usr/lib/apache2/modules/mod_weed.so
```

Or copy manually:

```bash
sudo cp build/mod_weed.so /usr/lib/apache2/modules/
sudo install -m 755 build/weed /usr/local/bin/weed
```

---

## Signing keys

Archives are **always signed**. Generate a **4096-bit RSA** key pair once; keep the private key on the build machine only.

```bash
# Private key (CI / build host — secret)
openssl genrsa -out weed_priv.pem 4096

# Public key (servers — not secret, but treat as config)
openssl rsa -in weed_priv.pem -pubout -out weed_pub.pem
```

- Pack with **private** PEM (`-k weed_priv.pem`)
- Apache loads with **public** PEM (`WeedPublicKey`)

Rotate by generating a new pair, repacking, distributing the new public key, then the new `.weed`.

---

## Packing

### Directory

```bash
weed pack -o site.weed -k weed_priv.pem --compress br,gzip ./dist
```

### File list on stdin (any tool)

Paths are relative to the current directory, or to `-C`:

```bash
# After a build that wrote into dist/
find dist -type f -printf '%P\n' \
  | weed pack -o site.weed -k weed_priv.pem --compress br,gzip -C dist -

# Or tracked files only (example)
git ls-files | weed pack -o site.weed -k weed_priv.pem --compress br -
```

### Options

| Flag | Meaning |
|------|---------|
| `-o path` | Output `.weed` (required) |
| `-k priv.pem` | RSA-4096 private key PEM (required) |
| `-r name` | Root document filename at archive root (default `index.html`); stored as path `""` for `/` |
| `-C dir` | Base directory when reading paths from stdin |
| `--compress br,gzip` | Store br/gzip twins when **smaller** than identity (`-z` alias) |
| `-` | Read paths from stdin (one per line; empty lines skipped) |

### Path rules (important)

- Paths are **UTF-8 NFC**, no leading `/`, no `..`
- Relative to pack root (directory mode) or list/`-C` (list mode)
- Symlinks are **followed**; file content is stored
- Root document (`-r`, default `index.html` at the top of the tree) becomes archive path **`""`** (serves `/`)

---

## Apache configuration

### Load the module

Debian-style:

```apache
# /etc/apache2/mods-available/weed.load
LoadModule weed_module /usr/lib/apache2/modules/mod_weed.so
```

```bash
sudo a2enmod weed
```

Or a single snippet in a vhost / conf file:

```apache
LoadModule weed_module /usr/lib/apache2/modules/mod_weed.so
```

### Serve a site

Minimal vhost (or `<Location>`):

```apache
<VirtualHost *:443>
    ServerName app.example.com
    # SSLEngine … as usual

    <Location />
        Require all granted
        SetHandler weed
        WeedArchive    /var/www/app/site.weed
        WeedPublicKey  /etc/weed/app.pub.pem
        WeedSpa        On
    </Location>
</VirtualHost>
```

| Directive | Required | Meaning |
|-----------|----------|---------|
| `SetHandler weed` | yes | Enable Weed for this location |
| `WeedArchive` | yes | Absolute path to `.weed` file |
| `WeedPublicKey` | yes | PEM public key (SubjectPublicKeyInfo) |
| `WeedSpa` | no | `On` / `Off` (default off). Unknown paths **without** a file extension serve the root document (`""`) — client-side routers |

Permissions:

```bash
sudo mkdir -p /var/www/app /etc/weed
sudo cp site.weed /var/www/app/site.weed
sudo cp weed_pub.pem /etc/weed/app.pub.pem
sudo chown root:www-data /var/www/app/site.weed
sudo chmod 640 /var/www/app/site.weed
sudo chown root:root /etc/weed/app.pub.pem
sudo chmod 644 /etc/weed/app.pub.pem
```

Apache must **read** the archive and the public key (`www-data` or your MPM user).

```bash
sudo apache2ctl configtest
sudo systemctl reload apache2
```

On successful load you should see something like:

```text
mod_weed: mmap'd /var/www/app/site.weed (N entries, … bytes, shared read-only)
```

If the signature fails or the version is wrong, Apache will refuse to start / reload that config (logged as emergency).

---

## Deploy workflow (recommended)

On the **build** machine:

```bash
npm run build   # or whatever produces dist/
weed pack -o site.weed -k /secrets/weed_priv.pem --compress br,gzip ./dist
scp site.weed deploy@server:/var/www/app/site.weed.new
```

On the **server** (atomic replace + reload):

```bash
sudo mv /var/www/app/site.weed.new /var/www/app/site.weed
sudo systemctl reload apache2
```

`reload` re-runs module config: signature verified again, archive re-mmap’d.  
**Last-Modified** becomes the load time of that generation.

Use the **same** `site.weed` and **same** public key on every server so the fleet stays identical.

---

## Runtime behaviour (module)

1. **Startup:** verify RSA signature → check format version `1` → mmap whole file `PROT_READ` / shared → keep index in the map  
2. **Request:** strip `Location` prefix → URL-decode → NFC → xxHash64 path → binary search  
3. **Encoding:** prefer `br` then `gzip` then identity from `Accept-Encoding`  
4. **SPA:** if `WeedSpa On` and path miss without extension → serve root `""`  
5. **Headers:** `Content-Type`, `Content-Length`, `ETag`, `Cache-Control`, `Last-Modified`, `Vary: Accept-Encoding`, optional `Content-Encoding`  
6. **304:** `If-None-Match` (ETag) preferred; else `If-Modified-Since` vs module load time  

Serving is zero-copy from the mmap (immortal buckets). No per-request `open` of the archive for body data.

---

## Cache policy (baked in at pack time)

No Apache knobs. MIME-driven defaults:

| Content | Cache-Control |
|---------|----------------|
| HTML / unknown | `no-cache, max-age=0` |
| CSS, JS, JSON, WASM, SVG | `public, must-revalidate, max-age=0` |
| Images, fonts | `public, max-age=604800` (7 days) |
| Audio / video | `public, max-age=86400` (1 day) |

**ETag** = XXH3-128 of the **stored body** (seed `0xEB`), strong validator.  
Stable URLs + revalidation; no need for Vite-style hashed filenames for correctness.

---

## Format (version 1, summary)

Everything is **little-endian** — so the archive **header lives at the end of the file** (the natural place for a header when you read the low end of the stream). Payload is written first; the catalog is appended as that LE header. Stream-friendly packing, same idea as putting a tape TOC after the data.

```text
u8  signature[512]     RSA-4096 PKCS#1 v1.5 over SHA-256 of everything after this field
FILEITEM...            streamed payload (starts at offset 512)

--- little-endian header (at EOF) ---
u64 path_hash[N]       xxHash64(path), seed 0; sorted by (hash, path, encoding)
u64 file_offset[N]     absolute offset of each FILEITEM
u8  reserved[16]       reserved[0]=1 (version); rest zeros
u64 file_count         N  (last 8 bytes of the file)
```

Reader: `N = u64le(file[size-8])`, header size = `16*N + 16 + 8`, header starts at `size - header_size`.

```text
FILEITEM:
  u64 content_len
  u32 path_len
  u32 mime_len
  u8  encoding           0=identity, 1=gzip, 2=br
  u8  cache_flags
  u32 max_age
  u8  etag[16]
  path, mime, content
```

Authoritative detail: `include/weed_format.h`.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Apache won’t start / reload | Error log: signature, version, missing archive, permissions |
| `unsupported archive version` | Repack with current `weed` (version 1) |
| `signature verification failed` | Wrong public key, truncated copy, or private key mismatch |
| 404 on `/` | Root file missing at pack root (`index.html` or `-r`); warning was printed at pack time |
| SPA deep links 404 | Set `WeedSpa On` |
| Missing `.js` returns HTML | Expected only for paths **without** extension when SPA is on; real asset 404s stay 404 |
| 403 | `Require all granted` on the Location; filesystem ACLs on `.weed` |
| Module not found | `LoadModule` path; `apache2ctl -M \| grep weed` |

```bash
# Config + modules
sudo apache2ctl configtest
apache2ctl -M 2>/dev/null | grep weed

# Logs
sudo journalctl -u apache2 -e
# or
sudo tail -f /var/log/apache2/error.log
```

---

## Security notes

- Private key never leaves the build/CI environment.
- Public key on servers is enough to **verify**, not to forge.
- Signature covers the entire archive after the signature field (including version and all files).
- Weed is **integrity/authenticity**, not confidentiality (no encryption of content).
- Refuse packing paths with `..`; module also rejects `..` after URL decode.

---

## Multi-server checklist

1. Build once → one `site.weed`  
2. Install same `mod_weed.so` and same `weed_pub.pem` on every node  
3. Copy the same `site.weed` everywhere  
4. Reload Apache  
5. Spot-check: `curl -sI https://host/` → same `ETag` for the same URL across nodes  

---

## License / project status

Format **v1**. Packer + Apache module are the supported surface. There is no separate unpacker required for production serving (the module is the reader).
