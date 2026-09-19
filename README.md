# AIK-Browser

**Android Image Kitchen In Browser** — unpack and repack Android `boot.img`, `recovery.img`, and `vendor_boot.img` files. Three tools, one shared format implementation: a browser app, a Python CLI, and a shell wrapper.

Supports boot image header versions v0–v4 and vendor_boot v3–v4 (legacy devices through modern GKI). **v1.1.0** adds AVB signing/verification, a diff mode, batch processing, and more — see [What's new](#whats-new-in-v110) below.

---

## Tools

| File | What it is | Requirements |
|---|---|---|
| [`aik-browser.html`](./aik-browser.html) | Single-file web app — drag, drop, unpack, edit, repack, sign | Any modern browser, no install |
| [`aik.py`](./aik.py) | Command-line unpack/repack/sign/diff | Python 3, stdlib only (optional `lz4`, `cryptography`) |
| [`aik.sh`](./aik.sh) | Shell wrapper around `aik.py`, plus batch processing | `bash`, `python3` |

<p align="center">
  <img src="./aik-py-demo.png" width="640" alt="aik.py running info, unpack, and repack against a boot.img">
  <br><em>aik.py</em>
</p>
<p align="center">
  <img src="./aik-sh-demo.png" width="640" alt="aik.sh running the same workflow">
  <br><em>aik.sh</em>
</p>

---

## What's new in v1.1.0

**All three tools:**
- **AVB (Android Verified Boot) signing and verification** — `sign` / `verify-sig` (CLI) and the **avb** tab (browser). Generates or imports an RSA key, builds a spec-accurate vbmeta + hash-footer (SHA256_RSA2048/4096), and verifies signatures, hashes, and tamper status. The Python and browser implementations were cross-validated to sign in one and verify in the other, in both directions, with matching results.
- **`diff`** — compares two images: header fields, section hashes/sizes, and file-by-file ramdisk contents (added/removed/modified).
- **`--verify`** on repack — re-parses the output afterward and confirms every section round-tripped correctly.
- **bzip2** support (compress and decompress), on top of the existing gzip/xz/lz4 — no extra dependency needed, it's Python/browser stdlib.

**AIK-Browser only:**
- **Hex viewer** — paginated hex/ASCII dump of any section's raw bytes.
- **DTB inspector** — parses the flattened device tree blob (FDT) format and displays it as a browsable node/property tree, for `dtb` and `recovery_dtbo` sections.
- **fstab / \*.prop editor** — recognized config files in the ramdisk (`default.prop`, `*.prop`, `fstab*`) get an "edit as text" option with live syntax warnings (key=value shape, expected fstab column count) instead of raw binary upload/download.
- **Diff tab** — load a second image and compare it against the loaded one, right in the browser.
- **Batch tab** — drop several images at once and see a comparison table (format, header version, page size, total size, cmdline).
- **Session persistence** — the last-loaded file is cached in IndexedDB; reopening the page offers to restore it (the source file only, not in-progress edits).

**aik.sh only:**
- **`batch-unpack`** / **`batch-repack`** — process a whole directory of images in one command.
- **`.aikrc`** config file (project-local or `~/.aikrc`) for default paths.
- **`sign`** / **`verify`** / **`diff`** passthrough subcommands.

---

## AIK-Browser (web app)

Open `aik-browser.html` in a browser — no server, no build step. It loads `pako`, `JSZip`, and (optionally) `lz4js` from a CDN on first use; everything after that runs locally. No file is ever uploaded anywhere.

**What it does:**
- Auto-detects header version and image type from the magic bytes
- Decodes and displays every header field (page size, cmdline, os_version, addrs, etc.)
- Extracts each section (kernel, ramdisk, second stage, dtb, recovery_dtbo, vendor_ramdisk, bootconfig…) for individual download
- Parses the ramdisk as a cpio (`newc`) archive — browse, download, replace, delete, or add files, then rebuild the archive in place
- Repacks everything into a new image: recomputes header size, page-aligned section offsets, and (for header v0–v2) the SHA-1 `id` field
- Flags AVB footers on load, since a repacked image needs re-signing to pass verified boot

**Usage:**
1. Open `aik-browser.html`
2. Drop in a boot/recovery/vendor_boot image
3. Inspect the **Header** and **Sections** tabs
4. Edit ramdisk contents in the **Ramdisk** tab, if needed
5. Build and download from the **Repack** tab

---

## aik.py (CLI)

```bash
aik.py info   <image>
aik.py unpack <image> [-o outdir]
aik.py repack <workdir> [-o output.img]
```

**Example:**

```bash
python3 aik.py info boot.img
python3 aik.py unpack boot.img -o work/
# edit work/kernel.bin, or files under work/ramdisk-extracted/
python3 aik.py repack work/ -o boot-patched.img
```

`unpack` writes:
- `<section>.<ext>` for each section, still in its original compression (e.g. `kernel.bin`, `ramdisk.gz`)
- `<ramdisk>-extracted/` — the ramdisk's cpio contents as real files on disk
- `<ramdisk>.index.json` — file modes, ownership, and entries (symlinks, device nodes) that can't be represented as plain files
- `bootimg.json` — the full header, used by `repack` to rebuild an equivalent image

`repack` reads `bootimg.json` from a working directory, rebuilds the ramdisk cpio from the extracted tree (or uses a section file directly if you replaced it wholesale), and writes a new image with correct offsets and header fields.

**Optional dependency:**

```bash
pip install lz4
```

Needed only to *recompress* lz4-based ramdisks (common on Android 12+ GKI vendor_boot images) after editing them. Extraction and inspection work without it.

---

## aik.sh (shell wrapper)

Same operations as `aik.py`, with a default working directory and confirmation prompts before anything gets overwritten or deleted.

```bash
./aik.sh info   boot.img
./aik.sh unpack boot.img [workdir]      # default: ./aik-work
./aik.sh repack [workdir] [output.img]  # default: ./aik-work -> repacked.img
./aik.sh clean  [workdir]
```

`aik.py` must be in the same directory as `aik.sh`, or point `AIK_PY` at it:

```bash
AIK_PY=/path/to/aik.py ./aik.sh info boot.img
```

---

## Format support

| Header | Devices | Status |
|---|---|---|
| boot v0 / v1 / v2 | Legacy (pre-Android 11 non-GKI) | Full unpack + repack |
| boot v3 / v4 | GKI (Android 12+) | Full unpack + repack |
| vendor_boot v3 / v4 | GKI split images | Full unpack + repack |

**Compression:**

| Format | Detect | Decompress | Recompress |
|---|---|---|---|
| gzip | ✅ | ✅ | ✅ |
| lz4 (frame / legacy) | ✅ | ✅ (browser: needs `lz4js`; CLI: needs `pip install lz4`) | same requirement |
| xz | ✅ | ❌ | ❌ (passthrough only if unmodified) |
| bzip2 | ✅ | ❌ | ❌ (passthrough only if unmodified) |

Sections you don't touch are always carried through byte-for-byte on repack, regardless of their compression.

---

## Known limitations

- **AVB / verified boot:** signing is now supported (see above), but a key generated or imported here is only trusted by a device if that device's AVB trust store has actually been repointed at its public half — e.g. via a custom bootloader or vbmeta digest override on an unlocked device. It will never match a real device's factory verified-boot key. The implementation has been cross-validated between the Python and browser versions (sign in one, verify in the other, both directions) and tested against tampering and wrong-key scenarios, but has not been tested against a real device's bootloader/libavb.
- **xz / bzip2 ramdisks:** xz can be extracted as raw bytes but not decompressed for browsing/editing in-browser or via the CLI; bzip2 is now fully supported (extract, browse, edit, recompress) in both.
- **OEM header variants:** Samsung, some MediaTek, and other vendor-specific formats that diverge from AOSP's `bootimg.h` aren't handled.
- **Very large images on low-memory devices:** the browser app holds the whole image in memory; this can be slow on older phones with multi-hundred-MB images.

---

## How it works

All three tools implement the same format logic independently in their respective languages (JS / Python), based on the AOSP `bootimg.h` and vendor_boot header layouts. Header field offsets were validated against synthetic images before release — `aik.py unpack` followed by `aik.py repack` on an unmodified image reproduces the original byte-for-byte, aside from the `id` field on v0–v2 images (which is intentionally recomputed from actual section contents rather than trusted from the source).

---

