#!/usr/bin/env python3
"""
aik.py -- Android Image Kitchen (command-line)

Unpacks and repacks Android boot / recovery / vendor_boot images.
Supports boot image header v0-v4 and vendor_boot header v3-v4.

Companion CLI to AIK-Browser (the in-browser version of this tool).
No third-party dependencies required for boot.img / recovery.img work.
Optional: `pip install lz4` to recompress lz4-based ramdisks (common on
GKI / Android 12+ devices). Without it, lz4 sections are extracted fine
but repack falls back to passthrough for any lz4 section you did not
modify, and refuses to repack a *modified* lz4 section.

Usage:
  aik.py unpack  <image> [-o OUTDIR]
  aik.py repack  <workdir> [-o OUTPUT.img]
  aik.py info    <image>

Typical workflow:
  aik.py unpack boot.img -o work/
  # edit work/ramdisk/... , or replace work/kernel, work/ramdisk.cpio.gz
  aik.py repack work/ -o boot-new.img
"""

import argparse
import gzip
import hashlib
import json
import lzma
import os
import struct
import sys
import shutil

try:
    import lz4.frame as _lz4frame
    HAVE_LZ4 = True
except ImportError:
    HAVE_LZ4 = False


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def align(n, p):
    return ((n + p - 1) // p) * p


def read_cstr(buf, off, length):
    end = buf.index(b"\x00", off, off + length) if b"\x00" in buf[off:off + length] else off + length
    return buf[off:end].decode("utf-8", "replace")


def write_cstr(ba, off, length, s):
    b = s.encode("utf-8")[:length]
    ba[off:off + length] = b"\x00" * length
    ba[off:off + len(b)] = b


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024


# --------------------------------------------------------------------------
# compression
# --------------------------------------------------------------------------

def detect_compression(data):
    if len(data) >= 2 and data[0:2] == b"\x1f\x8b":
        return "gzip"
    if len(data) >= 4 and data[0:4] == b"\x02\x21\x4c\x18":
        return "lz4-legacy"
    if len(data) >= 4 and data[0:4] == b"\x04\x22\x4d\x18":
        return "lz4-frame"
    if len(data) >= 6 and data[0:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(data) >= 6 and data[0:6] == b"070701":
        return "cpio-newc"
    if len(data) >= 2 and data[0:2] == b"BZ":
        return "bzip2"
    return "raw"


def decompress(data, kind):
    if kind == "gzip":
        return gzip.decompress(data)
    if kind == "xz":
        return lzma.decompress(data)
    if kind in ("lz4-frame", "lz4-legacy"):
        if not HAVE_LZ4:
            return None
        return _lz4frame.decompress(data)
    return None  # cpio-newc / raw / bzip2 -> caller handles as-is


def recompress(data, kind):
    if kind == "gzip":
        return gzip.compress(data, compresslevel=9, mtime=0)
    if kind == "xz":
        return lzma.compress(data, format=lzma.FORMAT_XZ)
    if kind in ("lz4-frame", "lz4-legacy"):
        if not HAVE_LZ4:
            return None
        return _lz4frame.compress(data)
    return None  # raw / cpio-newc -> caller writes as-is


def ext_for(kind):
    return {"gzip": ".gz", "lz4-frame": ".lz4", "lz4-legacy": ".lz4",
            "xz": ".xz", "cpio-newc": ".cpio"}.get(kind, ".bin")


# --------------------------------------------------------------------------
# boot image header (v0-v4)
# --------------------------------------------------------------------------

def parse_boot_header(buf):
    if buf[0:8] != b"ANDROID!":
        return None
    header_version = struct.unpack_from("<I", buf, 40)[0]
    h = {"magic": "ANDROID!", "header_version": header_version}
    secs = []

    if header_version >= 3:
        h["kernel_size"] = struct.unpack_from("<I", buf, 8)[0]
        h["ramdisk_size"] = struct.unpack_from("<I", buf, 12)[0]
        h["os_version_raw"] = struct.unpack_from("<I", buf, 16)[0]
        h["header_size"] = struct.unpack_from("<I", buf, 20)[0]
        h["cmdline"] = read_cstr(buf, 44, 1536)
        h["page_size"] = 4096
        if header_version == 4:
            h["signature_size"] = struct.unpack_from("<I", buf, 44 + 1536)[0]
        off = align(h["header_size"], h["page_size"])
        secs.append(("kernel", off, h["kernel_size"])); off = align(off + h["kernel_size"], h["page_size"])
        secs.append(("ramdisk", off, h["ramdisk_size"])); off = align(off + h["ramdisk_size"], h["page_size"])
        if header_version == 4 and h.get("signature_size"):
            secs.append(("boot_signature", off, h["signature_size"]))
            off = align(off + h["signature_size"], h["page_size"])
    else:
        h["kernel_size"] = struct.unpack_from("<I", buf, 8)[0]
        h["kernel_addr"] = struct.unpack_from("<I", buf, 12)[0]
        h["ramdisk_size"] = struct.unpack_from("<I", buf, 16)[0]
        h["ramdisk_addr"] = struct.unpack_from("<I", buf, 20)[0]
        h["second_size"] = struct.unpack_from("<I", buf, 24)[0]
        h["second_addr"] = struct.unpack_from("<I", buf, 28)[0]
        h["tags_addr"] = struct.unpack_from("<I", buf, 32)[0]
        h["page_size"] = struct.unpack_from("<I", buf, 36)[0] or 2048
        h["os_version_raw"] = struct.unpack_from("<I", buf, 44)[0]
        h["name"] = read_cstr(buf, 48, 16)
        h["cmdline"] = read_cstr(buf, 64, 512)
        h["extra_cmdline"] = read_cstr(buf, 608, 1024)
        h["id_hex"] = buf[576:608].hex()
        if header_version == 0:
            h["header_size"] = 1632
        else:
            h["recovery_dtbo_size"] = struct.unpack_from("<I", buf, 1632)[0]
            h["recovery_dtbo_offset"] = struct.unpack_from("<Q", buf, 1636)[0]
            h["header_size"] = struct.unpack_from("<I", buf, 1644)[0]
            if header_version == 2:
                h["dtb_size"] = struct.unpack_from("<I", buf, 1648)[0]
                h["dtb_addr"] = struct.unpack_from("<Q", buf, 1652)[0]

        off = align(h["header_size"], h["page_size"])
        secs.append(("kernel", off, h["kernel_size"])); off = align(off + h["kernel_size"], h["page_size"])
        secs.append(("ramdisk", off, h["ramdisk_size"])); off = align(off + h["ramdisk_size"], h["page_size"])
        if h.get("second_size"):
            secs.append(("second", off, h["second_size"])); off = align(off + h["second_size"], h["page_size"])
        if h.get("recovery_dtbo_size"):
            secs.append(("recovery_dtbo", off, h["recovery_dtbo_size"])); off = align(off + h["recovery_dtbo_size"], h["page_size"])
        if h.get("dtb_size"):
            secs.append(("dtb", off, h["dtb_size"])); off = align(off + h["dtb_size"], h["page_size"])

    return {"kind": "boot", "header": h, "sections": secs}


def parse_vendor_boot_header(buf):
    if buf[0:8] != b"VNDRBOOT":
        return None
    h = {"magic": "VNDRBOOT"}
    h["header_version"] = struct.unpack_from("<I", buf, 8)[0]
    h["page_size"] = struct.unpack_from("<I", buf, 12)[0] or 4096
    h["kernel_addr"] = struct.unpack_from("<I", buf, 16)[0]
    h["ramdisk_addr"] = struct.unpack_from("<I", buf, 20)[0]
    h["vendor_ramdisk_size"] = struct.unpack_from("<I", buf, 24)[0]
    h["cmdline"] = read_cstr(buf, 28, 2048)
    h["tags_addr"] = struct.unpack_from("<I", buf, 2076)[0]
    h["name"] = read_cstr(buf, 2080, 16)
    h["header_size"] = struct.unpack_from("<I", buf, 2096)[0]
    h["dtb_size"] = struct.unpack_from("<I", buf, 2100)[0]
    h["dtb_addr"] = struct.unpack_from("<Q", buf, 2104)[0]

    secs = []
    if h["header_version"] >= 4:
        h["vendor_ramdisk_table_size"] = struct.unpack_from("<I", buf, 2112)[0]
        h["vendor_ramdisk_table_entry_num"] = struct.unpack_from("<I", buf, 2116)[0]
        h["vendor_ramdisk_table_entry_size"] = struct.unpack_from("<I", buf, 2120)[0]
        h["bootconfig_size"] = struct.unpack_from("<I", buf, 2124)[0]
        off = align(2128, h["page_size"])
    else:
        off = align(2112, h["page_size"])

    secs.append(("vendor_ramdisk", off, h["vendor_ramdisk_size"])); off = align(off + h["vendor_ramdisk_size"], h["page_size"])
    secs.append(("dtb", off, h["dtb_size"])); off = align(off + h["dtb_size"], h["page_size"])
    if h["header_version"] >= 4:
        if h.get("vendor_ramdisk_table_size"):
            secs.append(("vendor_ramdisk_table", off, h["vendor_ramdisk_table_size"]))
            off = align(off + h["vendor_ramdisk_table_size"], h["page_size"])
        if h.get("bootconfig_size"):
            secs.append(("bootconfig", off, h["bootconfig_size"]))
            off = align(off + h["bootconfig_size"], h["page_size"])

    return {"kind": "vendor_boot", "header": h, "sections": secs}


def detect_avb_footer(buf):
    if len(buf) < 64:
        return False
    return buf[len(buf) - 64:len(buf) - 60] == b"AVBf"


# --------------------------------------------------------------------------
# cpio (newc)
# --------------------------------------------------------------------------

def cpio_align4(n):
    return (n + 3) & ~3


def parse_cpio(buf):
    entries = []
    off = 0
    while off + 6 <= len(buf):
        magic = buf[off:off + 6]
        if magic not in (b"070701", b"070702"):
            break
        def hx(s, e):
            return int(buf[off + s:off + e], 16)
        mode = hx(14, 22)
        uid = hx(22, 30)
        gid = hx(30, 38)
        mtime = hx(46, 54)
        filesize = hx(54, 62)
        namesize = hx(94, 102)
        name_start = off + 110
        raw_name = buf[name_start:name_start + namesize - 1]
        name = raw_name.decode("utf-8", "replace")
        data_start = cpio_align4(name_start + namesize)
        if name == "TRAILER!!!":
            break
        entries.append({
            "name": name, "mode": mode, "uid": uid, "gid": gid,
            "mtime": mtime, "size": filesize, "data_start": data_start,
        })
        off = cpio_align4(data_start + filesize)
    return entries


def build_cpio(entries, data_for):
    chunks = []
    ino = 1
    for e in entries:
        data = data_for(e)
        name_b = e["name"].encode("utf-8") + b"\x00"
        hdr = ("070701"
               + f"{ino:08x}" + f"{e['mode']:08x}" + f"{e.get('uid',0):08x}" + f"{e.get('gid',0):08x}"
               + "00000001" + f"{e.get('mtime',0):08x}" + f"{len(data):08x}"
               + "00000000" * 4 + f"{len(name_b):08x}" + "00000000")
        hdr_b = hdr.encode("ascii")
        c1 = (hdr_b + name_b)
        c1 = c1 + b"\x00" * (cpio_align4(len(c1)) - len(c1))
        c2 = data + b"\x00" * (cpio_align4(len(data)) - len(data))
        chunks.append(c1)
        chunks.append(c2)
        ino += 1
    trailer_name = b"TRAILER!!!\x00"
    thdr = ("070701" + "00000000" * 4 + "00000001" + "00000000" + "00000000"
            + "00000000" * 4 + f"{len(trailer_name):08x}" + "00000000")
    thdr_b = thdr.encode("ascii")
    tc = thdr_b + trailer_name
    tc = tc + b"\x00" * (cpio_align4(len(tc)) - len(tc))
    chunks.append(tc)
    out = b"".join(chunks)
    pad = (-len(out)) % 512
    out += b"\x00" * pad
    return out


def mode_type_label(mode):
    t = (mode >> 12) & 0xF
    return {4: "dir", 8: "file", 0xA: "symlink", 1: "fifo", 2: "chr", 6: "blk", 0xC: "sock"}.get(t, "?")


# --------------------------------------------------------------------------
# id (sha1) recompute for header v0-v2, mirrors mkbootimg.py behaviour
# --------------------------------------------------------------------------

def compute_id_v0v2(section_bytes_by_name, order):
    sha = hashlib.sha1()
    for name in order:
        data = section_bytes_by_name.get(name, b"")
        sha.update(data)
        sha.update(struct.pack("<I", len(data)))
    digest = sha.digest()
    return digest + b"\x00" * (32 - len(digest))


def decode_os_version(raw):
    if not raw:
        return "0 (GKI / unset)"
    osv = raw >> 11
    patch = raw & 0x7ff
    a, b, c = (osv >> 14) & 0x7f, (osv >> 7) & 0x7f, osv & 0x7f
    py, pm = (patch >> 9) & 0x7f, patch & 0x0f
    return f"{a}.{b}.{c} (patch {2000+py}-{pm:02d})"


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_info(args):
    with open(args.image, "rb") as f:
        buf = f.read()
    parsed = parse_boot_header(buf) or parse_vendor_boot_header(buf)
    if not parsed:
        print("error: not a recognized boot/vendor_boot image (bad magic)", file=sys.stderr)
        sys.exit(1)
    h = parsed["header"]
    print(f"format          : {parsed['kind']}")
    print(f"header_version  : {h['header_version']}")
    print(f"page_size       : {h['page_size']}")
    for k, v in h.items():
        if k in ("header_version", "page_size", "magic"):
            continue
        print(f"{k:<16}: {v}")
    if parsed["kind"] == "boot":
        print(f"os_version      : {decode_os_version(h.get('os_version_raw', 0))}")
    print()
    print("sections:")
    for name, off, size in parsed["sections"]:
        if size == 0:
            continue
        data = buf[off:off + size]
        kind = detect_compression(data)
        print(f"  {name:<20} offset=0x{off:x}  size={size}  compression={kind}")
    if detect_avb_footer(buf):
        print()
        print("warning: AVB footer detected. Repacking will invalidate verified boot")
        print("         signing; re-sign the output with avbtool if you need it to")
        print("         pass verification.")


def cmd_unpack(args):
    with open(args.image, "rb") as f:
        buf = f.read()
    parsed = parse_boot_header(buf) or parse_vendor_boot_header(buf)
    if not parsed:
        print("error: not a recognized boot/vendor_boot image (bad magic)", file=sys.stderr)
        sys.exit(1)

    outdir = args.outdir or (os.path.splitext(os.path.basename(args.image))[0] + "-unpacked")
    os.makedirs(outdir, exist_ok=True)
    kind = parsed["kind"]
    h = parsed["header"]

    meta = {"kind": kind, "header": h, "avb_footer": detect_avb_footer(buf), "sections": {}}

    for name, off, size in parsed["sections"]:
        if size == 0:
            continue
        data = buf[off:off + size]
        comp = detect_compression(data)
        meta["sections"][name] = {"compression": comp, "size": size}
        fn = os.path.join(outdir, f"{name}{ext_for(comp)}")
        with open(fn, "wb") as f:
            f.write(data)
        print(f"  wrote {fn}  ({human(size)}, {comp})")

        ramdisk_names = ("ramdisk", "vendor_ramdisk")
        if name in ramdisk_names:
            plain = data
            if comp != "cpio-newc":
                dec = decompress(data, comp)
                if dec is not None:
                    plain = dec
                elif comp not in ("raw",):
                    print(f"  ! could not decompress {name} ({comp}); skipping ramdisk extraction")
                    plain = None
            if plain is not None and detect_compression(plain) == "cpio-newc":
                entries = parse_cpio(plain)
                rd_dir = os.path.join(outdir, f"{name}-extracted")
                os.makedirs(rd_dir, exist_ok=True)
                index = []
                for e in entries:
                    t = mode_type_label(e["mode"])
                    index.append({"name": e["name"], "mode": e["mode"], "uid": e["uid"],
                                   "gid": e["gid"], "mtime": e["mtime"], "type": t})
                    if t == "dir":
                        os.makedirs(os.path.join(rd_dir, e["name"]) or rd_dir, exist_ok=True)
                    elif t == "file":
                        path = os.path.join(rd_dir, e["name"])
                        os.makedirs(os.path.dirname(path), exist_ok=True)
                        with open(path, "wb") as f:
                            f.write(plain[e["data_start"]:e["data_start"] + e["size"]])
                    # symlinks / device nodes / fifo / socket are recorded in the
                    # index but not materialized on disk (not all host filesystems
                    # support them faithfully) -- repack restores them from the index.
                with open(os.path.join(rd_dir, "..", f"{name}.index.json").replace("../", ""), "w") as f:
                    pass  # placeholder to keep path simple below
                with open(os.path.join(outdir, f"{name}.index.json"), "w") as f:
                    json.dump(index, f, indent=2)
                print(f"  extracted {len(entries)} entries -> {rd_dir}/  (index: {name}.index.json)")

    with open(os.path.join(outdir, "bootimg.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\nheader metadata written to {os.path.join(outdir, 'bootimg.json')}")
    if meta["avb_footer"]:
        print("warning: AVB footer detected on source image -- see 'info' output for details.")


def cmd_repack(args):
    workdir = args.workdir
    meta_path = os.path.join(workdir, "bootimg.json")
    if not os.path.isfile(meta_path):
        print(f"error: {meta_path} not found (run 'unpack' first, or point at that output dir)", file=sys.stderr)
        sys.exit(1)
    with open(meta_path) as f:
        meta = json.load(f)

    h = meta["header"]
    kind = meta["kind"]
    page_size = h["page_size"]

    final_bytes = {}
    for name, info in meta["sections"].items():
        comp = info["compression"]
        rd_dir = os.path.join(workdir, f"{name}-extracted")
        index_path = os.path.join(workdir, f"{name}.index.json")
        if os.path.isdir(rd_dir) and os.path.isfile(index_path):
            with open(index_path) as f:
                index = json.load(f)
            entries = []
            for e in index:
                entries.append({"name": e["name"], "mode": e["mode"], "uid": e["uid"],
                                 "gid": e["gid"], "mtime": e["mtime"]})

            def data_for(e, rd_dir=rd_dir):
                t = mode_type_label(e["mode"])
                if t != "file":
                    return b""
                path = os.path.join(rd_dir, e["name"])
                if os.path.isfile(path):
                    with open(path, "rb") as f:
                        return f.read()
                return b""

            plain = build_cpio(entries, data_for)
            if comp in ("raw", "cpio-newc"):
                out = plain
            else:
                out = recompress(plain, comp)
                if out is None:
                    print(f"error: cannot recompress {name} as {comp} "
                          f"(install `lz4` python package for lz4 support)", file=sys.stderr)
                    sys.exit(1)
            final_bytes[name] = out
            print(f"  rebuilt {name} from {rd_dir}/  ({len(entries)} entries, "
                  f"{human(len(plain))} -> {human(len(out))} as {comp})")
        else:
            fn = os.path.join(workdir, f"{name}{ext_for(comp)}")
            if not os.path.isfile(fn):
                print(f"error: expected section file {fn} not found", file=sys.stderr)
                sys.exit(1)
            with open(fn, "rb") as f:
                final_bytes[name] = f.read()

    order = [n for n, _, sz in (parse_boot_header_order(h, kind))]

    if kind == "boot":
        if h["header_version"] >= 3:
            header_size = 44 + 1536 + (4 if h["header_version"] == 4 else 0)
        elif h["header_version"] == 0:
            header_size = 1632
        elif h["header_version"] == 1:
            header_size = 1648
        else:
            header_size = 1660

        off = align(header_size, page_size)
        placements = {}
        for name in order:
            data = final_bytes.get(name, b"")
            if not data:
                continue
            placements[name] = (off, len(data), data)
            off = align(off + len(data), page_size)
        total = off
        out = bytearray(total)
        out[0:8] = b"ANDROID!"

        if h["header_version"] >= 3:
            struct.pack_into("<I", out, 8, len(placements.get("kernel", (0, 0, b""))[2]))
            struct.pack_into("<I", out, 12, len(placements.get("ramdisk", (0, 0, b""))[2]))
            struct.pack_into("<I", out, 16, h.get("os_version_raw", 0))
            struct.pack_into("<I", out, 20, header_size)
            struct.pack_into("<I", out, 40, h["header_version"])
            write_cstr(out, 44, 1536, h.get("cmdline", ""))
            if h["header_version"] == 4:
                struct.pack_into("<I", out, 44 + 1536, len(placements.get("boot_signature", (0, 0, b""))[2]))
        else:
            struct.pack_into("<I", out, 8, len(placements.get("kernel", (0, 0, b""))[2]))
            struct.pack_into("<I", out, 12, h.get("kernel_addr", 0))
            struct.pack_into("<I", out, 16, len(placements.get("ramdisk", (0, 0, b""))[2]))
            struct.pack_into("<I", out, 20, h.get("ramdisk_addr", 0))
            struct.pack_into("<I", out, 24, len(placements.get("second", (0, 0, b""))[2]))
            struct.pack_into("<I", out, 28, h.get("second_addr", 0))
            struct.pack_into("<I", out, 32, h.get("tags_addr", 0))
            struct.pack_into("<I", out, 36, page_size)
            struct.pack_into("<I", out, 40, h["header_version"])
            struct.pack_into("<I", out, 44, h.get("os_version_raw", 0))
            write_cstr(out, 48, 16, h.get("name", ""))
            write_cstr(out, 64, 512, h.get("cmdline", ""))
            write_cstr(out, 608, 1024, h.get("extra_cmdline", ""))

            id_order = ["kernel", "ramdisk", "second"]
            if h["header_version"] >= 1:
                id_order.append("recovery_dtbo")
            if h["header_version"] == 2:
                id_order.append("dtb")
            id_bytes = {n: placements[n][2] for n in id_order if n in placements}
            out[576:608] = compute_id_v0v2(id_bytes, id_order)

            if h["header_version"] >= 1:
                rd = placements.get("recovery_dtbo")
                struct.pack_into("<I", out, 1632, len(rd[2]) if rd else 0)
                struct.pack_into("<Q", out, 1636, rd[0] if rd else 0)
                struct.pack_into("<I", out, 1644, header_size)
                if h["header_version"] == 2:
                    dtb = placements.get("dtb")
                    struct.pack_into("<I", out, 1648, len(dtb[2]) if dtb else 0)
                    struct.pack_into("<Q", out, 1652, dtb[0] if dtb else 0)

        for name, (o, sz, data) in placements.items():
            out[o:o + sz] = data

    else:  # vendor_boot
        header_size = 2128 if h["header_version"] >= 4 else 2112
        off = align(header_size, page_size)
        placements = {}
        for name in order:
            data = final_bytes.get(name, b"")
            if not data:
                continue
            placements[name] = (off, len(data), data)
            off = align(off + len(data), page_size)
        total = off
        out = bytearray(total)
        out[0:8] = b"VNDRBOOT"
        struct.pack_into("<I", out, 8, h["header_version"])
        struct.pack_into("<I", out, 12, page_size)
        struct.pack_into("<I", out, 16, h.get("kernel_addr", 0))
        struct.pack_into("<I", out, 20, h.get("ramdisk_addr", 0))
        struct.pack_into("<I", out, 24, len(placements.get("vendor_ramdisk", (0, 0, b""))[2]))
        write_cstr(out, 28, 2048, h.get("cmdline", ""))
        struct.pack_into("<I", out, 2076, h.get("tags_addr", 0))
        write_cstr(out, 2080, 16, h.get("name", ""))
        struct.pack_into("<I", out, 2096, header_size)
        struct.pack_into("<I", out, 2100, len(placements.get("dtb", (0, 0, b""))[2]))
        struct.pack_into("<Q", out, 2104, h.get("dtb_addr", 0))
        if h["header_version"] >= 4:
            struct.pack_into("<I", out, 2112, len(placements.get("vendor_ramdisk_table", (0, 0, b""))[2]))
            struct.pack_into("<I", out, 2116, h.get("vendor_ramdisk_table_entry_num", 0))
            struct.pack_into("<I", out, 2120, h.get("vendor_ramdisk_table_entry_size", 0))
            struct.pack_into("<I", out, 2124, len(placements.get("bootconfig", (0, 0, b""))[2]))
        for name, (o, sz, data) in placements.items():
            out[o:o + sz] = data

    output = args.output or "repacked.img"
    with open(output, "wb") as f:
        f.write(out)
    print(f"\nwrote {output}  ({human(len(out))})")
    if meta.get("avb_footer"):
        print("warning: source image had an AVB footer. This output is unsigned;")
        print("         re-sign with avbtool if verified boot needs to pass.")


def parse_boot_header_order(h, kind):
    """Reconstruct section order/list the same way the parser does, from stored metadata."""
    secs = []
    if kind == "boot":
        if h["header_version"] >= 3:
            secs.append(("kernel", 0, h.get("kernel_size", 0)))
            secs.append(("ramdisk", 0, h.get("ramdisk_size", 0)))
            if h["header_version"] == 4 and h.get("signature_size"):
                secs.append(("boot_signature", 0, h["signature_size"]))
        else:
            secs.append(("kernel", 0, h.get("kernel_size", 0)))
            secs.append(("ramdisk", 0, h.get("ramdisk_size", 0)))
            if h.get("second_size"):
                secs.append(("second", 0, h["second_size"]))
            if h.get("recovery_dtbo_size"):
                secs.append(("recovery_dtbo", 0, h["recovery_dtbo_size"]))
            if h.get("dtb_size"):
                secs.append(("dtb", 0, h["dtb_size"]))
    else:
        secs.append(("vendor_ramdisk", 0, h.get("vendor_ramdisk_size", 0)))
        secs.append(("dtb", 0, h.get("dtb_size", 0)))
        if h["header_version"] >= 4:
            if h.get("vendor_ramdisk_table_size"):
                secs.append(("vendor_ramdisk_table", 0, h["vendor_ramdisk_table_size"]))
            if h.get("bootconfig_size"):
                secs.append(("bootconfig", 0, h["bootconfig_size"]))
    return secs


def main():
    p = argparse.ArgumentParser(prog="aik.py", description="Android Image Kitchen (command-line)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="print header + section info for an image")
    p_info.add_argument("image")
    p_info.set_defaults(func=cmd_info)

    p_unpack = sub.add_parser("unpack", help="unpack an image into a working directory")
    p_unpack.add_argument("image")
    p_unpack.add_argument("-o", "--outdir", default=None)
    p_unpack.set_defaults(func=cmd_unpack)

    p_repack = sub.add_parser("repack", help="repack a working directory into an image")
    p_repack.add_argument("workdir")
    p_repack.add_argument("-o", "--output", default=None)
    p_repack.set_defaults(func=cmd_repack)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
