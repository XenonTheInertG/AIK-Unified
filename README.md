# AIK-Browser

**Android Image Kitchen In Browser** — unpack and repack Android `boot.img`, `recovery.img`, and `vendor_boot.img` files. Three tools, one shared format implementation: a browser app, a Python CLI, and a shell wrapper.

Supports boot image header versions v0–v4 and vendor_boot v3–v4 (legacy devices through modern GKI).

---

## Tools

| File | What it is | Requirements |
|---|---|---|
| [`aik-browser.html`](./aik-browser.html) | Single-file web app — drag, drop, unpack, edit, repack | Any modern browser, no install |
| [`aik.py`](./aik.py) | Command-line unpack/repack | Python 3, stdlib only (optional `lz4` package) |
| [`aik.sh`](./aik.sh) | Shell wrapper around `aik.py` with a familiar unpack/repack workflow | `bash`, `python3` |

<p align="center">
  <img src="./aik-py-demo.png" width="640" alt="aik.py running info, unpack, and repack against a boot.img">
  <br><em>aik.py</em>
</p>
<p align="center">
  <img src="./aik-sh-demo.png" width="640" alt="aik.sh running the same workflow">
  <br><em>aik.sh</em>
</p>

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

- **AVB / verified boot:** a repacked image is unsigned. If the source image had an AVB footer, all three tools warn about it — re-sign the output yourself with `avbtool` if the device needs verified boot to pass.
- **xz / bzip2 ramdisks:** can be extracted as raw bytes but not decompressed for browsing/editing in-browser; the CLI has the same limit unless you decompress them externally first.
- **OEM header variants:** Samsung, some MediaTek, and other vendor-specific formats that diverge from AOSP's `bootimg.h` aren't handled.
- **Very large images on low-memory devices:** the browser app holds the whole image in memory; this can be slow on older phones with multi-hundred-MB images.

---

## How it works

All three tools implement the same format logic independently in their respective languages (JS / Python), based on the AOSP `bootimg.h` and vendor_boot header layouts. Header field offsets were validated against synthetic images before release — `aik.py unpack` followed by `aik.py repack` on an unmodified image reproduces the original byte-for-byte, aside from the `id` field on v0–v2 images (which is intentionally recomputed from actual section contents rather than trusted from the source).

---

## License

Add a license of your choice here (MIT is a common pick for tooling like this).
