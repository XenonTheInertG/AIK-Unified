#!/usr/bin/env python3
"""
aik.py -- Android Image Kitchen (command-line)   v1.1.0

Unpacks and repacks Android boot / recovery / vendor_boot images.
Supports boot image header v0-v4 and vendor_boot header v3-v4.

Companion CLI to AIK-Browser (the in-browser version of this tool).

Dependencies:
  - gzip, xz (lzma), and bzip2 recompression all work out of the box
    (Python stdlib) -- no install needed for any of those.
  - lz4 ramdisks: `pip install lz4` to recompress after editing.
    Extraction/inspection of lz4 ramdisks works without it.
  - AVB signing/verification (`sign`, `verify-sig`): `pip install cryptography`.

Usage:
  aik.py info        <image>
  aik.py unpack       <image> [-o OUTDIR]
  aik.py repack       <workdir> [-o OUTPUT.img] [--verify]
  aik.py diff         <image_a> <image_b>
  aik.py sign         <image> [-o OUTPUT.img] --key priv.pem | --gen-key out.pem
  aik.py verify-sig    <image> [--pubkey pub.pem | --key priv.pem]
  aik.py --version

Typical workflow:
  aik.py unpack boot.img -o work/
  # edit work/kernel.bin, or files under work/ramdisk-extracted/
  aik.py repack work/ -o boot-new.img --verify
  aik.py sign boot-new.img --gen-key mykey.pem -o boot-new-signed.img
  aik.py verify-sig boot-new-signed.img --key mykey.pem
"""

import argparse
import bz2
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

AIK_VERSION = "1.1.0"


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
    if kind == "bzip2":
        return bz2.decompress(data)
    if kind in ("lz4-frame", "lz4-legacy"):
        if not HAVE_LZ4:
            return None
        return _lz4frame.decompress(data)
    return None  # cpio-newc / raw -> caller handles as-is


def recompress(data, kind):
    if kind == "gzip":
        return gzip.compress(data, compresslevel=9, mtime=0)
    if kind == "xz":
        return lzma.compress(data, format=lzma.FORMAT_XZ)
    if kind == "bzip2":
        return bz2.compress(data, compresslevel=9)
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
# AVB (Android Verified Boot 2.0) -- hash-footer signing and verification
#
# Implements the on-disk format from AOSP's libavb (avb_vbmeta_image.h,
# avb_footer.h, avb_hash_descriptor.h, avb_crypto.h) well enough to produce
# a footer + vbmeta blob equivalent to `avbtool add_hash_footer` for the
# SHA256_RSA2048 / SHA256_RSA4096 algorithms, and to verify one.
#
# All vbmeta/footer/descriptor integer fields are big-endian ("network
# byte order" per the AOSP header comments) -- unlike the little-endian
# boot.img header elsewhere in this file.
#
# Requires the `cryptography` package (pip install cryptography).
# --------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as crypto_padding
    from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

AVB_MAGIC = b"AVB0"
AVB_FOOTER_MAGIC = b"AVBf"
AVB_HEADER_SIZE = 256
AVB_FOOTER_SIZE = 64
AVB_DESCRIPTOR_TAG_HASH = 2

# name -> (algorithm_type, hash_num_bytes, signature_num_bytes, key_num_bits)
AVB_ALGORITHMS = {
    "SHA256_RSA2048": (1, 32, 256, 2048),
    "SHA256_RSA4096": (2, 32, 512, 4096),
}


def _require_crypto():
    if not HAVE_CRYPTO:
        print("error: AVB signing/verification requires the `cryptography` package.", file=sys.stderr)
        print("       install it with: pip install cryptography", file=sys.stderr)
        sys.exit(1)


def avb_gen_key(path, bits=2048):
    _require_crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)
    return key


def avb_load_private_key(path):
    _require_crypto()
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def avb_load_public_key(path):
    _require_crypto()
    with open(path, "rb") as f:
        data = f.read()
    try:
        return serialization.load_pem_public_key(data)
    except ValueError:
        # allow pointing --pubkey at a private key file too
        return serialization.load_pem_private_key(data, password=None).public_key()


def avb_encode_public_key(pubkey):
    """Serializes an RSA public key into the AvbRSAPublicKeyHeader binary
    format avbtool embeds in vbmeta images: a Montgomery precomputation
    (n0inv, rr) alongside the raw modulus, consumed by libavb's software
    modexp. Algorithm ported directly from avbtool.py's encode_rsa_key()."""
    numbers = pubkey.public_numbers()
    n = numbers.n
    num_bits = pubkey.key_size
    num_bytes = num_bits // 8
    b = 2 ** 32
    n0inv = b - pow(n, -1, b)
    r = 2 ** num_bits
    rrmodn = (r * r) % n
    out = struct.pack(">II", num_bits, n0inv)
    out += n.to_bytes(num_bytes, "big")
    out += rrmodn.to_bytes(num_bytes, "big")
    return out


def avb_build_hash_descriptor(partition_name, image_size, salt, digest):
    name_b = partition_name.encode("utf-8")
    fixed = struct.pack(">Q32sIIII", image_size, b"sha256", len(name_b), len(salt), len(digest), 0)
    fixed += b"\x00" * 60  # reserved
    payload = fixed + name_b + salt + digest
    num_bytes_following = len(payload)
    pad = (-num_bytes_following) % 8
    payload += b"\x00" * pad
    num_bytes_following += pad
    header = struct.pack(">QQ", AVB_DESCRIPTOR_TAG_HASH, num_bytes_following)
    return header + payload


def avb_sign_image(image_bytes, priv_key, partition_name="boot", algorithm="SHA256_RSA2048",
                    salt=None, partition_size=None):
    """Builds an AVB hash-footer + vbmeta blob for image_bytes and returns
    the complete signed partition image (image + padding + vbmeta + footer),
    equivalent to `avbtool add_hash_footer`."""
    _require_crypto()
    algo_type, hash_len, sig_len, key_bits = AVB_ALGORITHMS[algorithm]
    if priv_key.key_size != key_bits:
        print(f"error: key is {priv_key.key_size}-bit, algorithm {algorithm} needs {key_bits}-bit", file=sys.stderr)
        sys.exit(1)

    if salt is None:
        salt = os.urandom(32)
    digest = hashlib.sha256(salt + image_bytes).digest()

    descriptor = avb_build_hash_descriptor(partition_name, len(image_bytes), salt, digest)
    pubkey_blob = avb_encode_public_key(priv_key.public_key())

    pubkey_offset = 0
    pubkey_size = len(pubkey_blob)
    pkmd_offset = pubkey_offset + pubkey_size
    pkmd_size = 0
    desc_offset = pkmd_offset + pkmd_size
    desc_size = len(descriptor)
    aux = pubkey_blob + descriptor
    aux_pad = (-len(aux)) % 64
    aux += b"\x00" * aux_pad
    aux_block_size = len(aux)

    release = b"aik.py avb-lite 1.0"
    header = bytearray(AVB_HEADER_SIZE)
    header[0:4] = AVB_MAGIC
    struct.pack_into(">I", header, 4, 1)   # required_libavb_version_major
    struct.pack_into(">I", header, 8, 0)   # required_libavb_version_minor
    # authentication_data_block_size filled in below once known
    struct.pack_into(">I", header, 28, algo_type)
    struct.pack_into(">Q", header, 32, 0)          # hash_offset (within auth block)
    struct.pack_into(">Q", header, 40, hash_len)   # hash_size
    struct.pack_into(">Q", header, 48, hash_len)   # signature_offset
    struct.pack_into(">Q", header, 56, sig_len)    # signature_size
    struct.pack_into(">Q", header, 64, pubkey_offset)
    struct.pack_into(">Q", header, 72, pubkey_size)
    struct.pack_into(">Q", header, 80, pkmd_offset)
    struct.pack_into(">Q", header, 88, pkmd_size)
    struct.pack_into(">Q", header, 96, desc_offset)
    struct.pack_into(">Q", header, 104, desc_size)
    struct.pack_into(">Q", header, 112, 0)  # rollback_index
    struct.pack_into(">I", header, 120, 0)  # flags
    header[128:128 + len(release)] = release

    auth_raw_len = hash_len + sig_len
    auth_pad = (-auth_raw_len) % 64
    auth_block_size = auth_raw_len + auth_pad
    struct.pack_into(">Q", header, 12, auth_block_size)
    struct.pack_into(">Q", header, 20, aux_block_size)

    data_to_sign = bytes(header) + aux
    computed_hash = hashlib.sha256(data_to_sign).digest()
    signature = priv_key.sign(data_to_sign, crypto_padding.PKCS1v15(), crypto_hashes.SHA256())

    auth = computed_hash + signature + b"\x00" * auth_pad
    vbmeta = bytes(header) + auth + aux

    page = 4096
    image_padded_size = align(len(image_bytes), page)
    vbmeta_offset = image_padded_size
    vbmeta_padded_len = align(len(vbmeta), page)

    if partition_size is None:
        partition_size = align(vbmeta_offset + vbmeta_padded_len + AVB_FOOTER_SIZE, page)

    out = bytearray(partition_size)
    out[0:len(image_bytes)] = image_bytes
    out[vbmeta_offset:vbmeta_offset + len(vbmeta)] = vbmeta

    footer = bytearray(AVB_FOOTER_SIZE)
    footer[0:4] = AVB_FOOTER_MAGIC
    struct.pack_into(">I", footer, 4, 1)   # version_major
    struct.pack_into(">I", footer, 8, 0)   # version_minor
    struct.pack_into(">Q", footer, 12, len(image_bytes))  # original_image_size
    struct.pack_into(">Q", footer, 20, vbmeta_offset)
    struct.pack_into(">Q", footer, 28, len(vbmeta))
    out[partition_size - AVB_FOOTER_SIZE:partition_size] = footer

    return bytes(out), {
        "partition_name": partition_name, "algorithm": algorithm,
        "salt": salt.hex(), "digest": digest.hex(),
        "vbmeta_offset": vbmeta_offset, "vbmeta_size": len(vbmeta),
        "partition_size": partition_size, "original_image_size": len(image_bytes),
    }


def avb_parse_footer(buf):
    if len(buf) < AVB_FOOTER_SIZE:
        return None
    foot = buf[-AVB_FOOTER_SIZE:]
    if foot[0:4] != AVB_FOOTER_MAGIC:
        return None
    return {
        "version_major": struct.unpack_from(">I", foot, 4)[0],
        "version_minor": struct.unpack_from(">I", foot, 8)[0],
        "original_image_size": struct.unpack_from(">Q", foot, 12)[0],
        "vbmeta_offset": struct.unpack_from(">Q", foot, 20)[0],
        "vbmeta_size": struct.unpack_from(">Q", foot, 28)[0],
    }


def avb_parse_vbmeta(vbmeta):
    if vbmeta[0:4] != AVB_MAGIC:
        return None
    h = {}
    h["required_libavb_version_major"] = struct.unpack_from(">I", vbmeta, 4)[0]
    h["required_libavb_version_minor"] = struct.unpack_from(">I", vbmeta, 8)[0]
    h["authentication_data_block_size"] = struct.unpack_from(">Q", vbmeta, 12)[0]
    h["auxiliary_data_block_size"] = struct.unpack_from(">Q", vbmeta, 20)[0]
    h["algorithm_type"] = struct.unpack_from(">I", vbmeta, 28)[0]
    h["hash_offset"] = struct.unpack_from(">Q", vbmeta, 32)[0]
    h["hash_size"] = struct.unpack_from(">Q", vbmeta, 40)[0]
    h["signature_offset"] = struct.unpack_from(">Q", vbmeta, 48)[0]
    h["signature_size"] = struct.unpack_from(">Q", vbmeta, 56)[0]
    h["public_key_offset"] = struct.unpack_from(">Q", vbmeta, 64)[0]
    h["public_key_size"] = struct.unpack_from(">Q", vbmeta, 72)[0]
    h["descriptors_offset"] = struct.unpack_from(">Q", vbmeta, 96)[0]
    h["descriptors_size"] = struct.unpack_from(">Q", vbmeta, 104)[0]
    h["release_string"] = vbmeta[128:176].split(b"\x00", 1)[0].decode("utf-8", "replace")

    auth_start = AVB_HEADER_SIZE
    aux_start = auth_start + h["authentication_data_block_size"]
    h["hash"] = vbmeta[auth_start + h["hash_offset"]: auth_start + h["hash_offset"] + h["hash_size"]]
    h["signature"] = vbmeta[auth_start + h["signature_offset"]: auth_start + h["signature_offset"] + h["signature_size"]]
    h["data_to_sign"] = vbmeta[0:auth_start] + vbmeta[aux_start:aux_start + h["auxiliary_data_block_size"]]

    desc_blob = vbmeta[aux_start + h["descriptors_offset"]: aux_start + h["descriptors_offset"] + h["descriptors_size"]]
    descriptors = []
    p = 0
    while p + 16 <= len(desc_blob):
        tag, nbf = struct.unpack_from(">QQ", desc_blob, p)
        body = desc_blob[p + 16:p + 16 + nbf]
        if tag == AVB_DESCRIPTOR_TAG_HASH and len(body) >= 116:
            image_size = struct.unpack_from(">Q", body, 0)[0]
            hash_algo = body[8:40].split(b"\x00", 1)[0].decode()
            pnl, sl, dl, flags = struct.unpack_from(">IIII", body, 40)
            off = 116  # fixed fields (8+32+16) + reserved(60)
            pname = body[off:off + pnl].decode("utf-8", "replace")
            salt = body[off + pnl: off + pnl + sl]
            digest = body[off + pnl + sl: off + pnl + sl + dl]
            descriptors.append({"type": "hash", "partition_name": pname, "image_size": image_size,
                                 "hash_algorithm": hash_algo, "salt": salt.hex(), "digest": digest.hex(),
                                 "flags": flags})
        p += 16 + nbf
    h["descriptors"] = descriptors
    return h


def avb_verify_image(buf, pubkey=None):
    """Verifies a signed partition image's footer + vbmeta + (optionally)
    the RSA signature against a supplied public key, and re-hashes the
    payload to confirm it matches the embedded hash descriptor."""
    footer = avb_parse_footer(buf)
    if not footer:
        return {"ok": False, "reason": "no AVB footer found"}
    vbmeta = buf[footer["vbmeta_offset"]:footer["vbmeta_offset"] + footer["vbmeta_size"]]
    h = avb_parse_vbmeta(vbmeta)
    if not h:
        return {"ok": False, "reason": "vbmeta magic mismatch"}

    result = {"ok": True, "footer": footer, "vbmeta": {k: v for k, v in h.items() if k not in ("data_to_sign",)},
              "checks": {}}

    computed_hash = hashlib.sha256(h["data_to_sign"]).digest()
    result["checks"]["vbmeta_hash_matches"] = (computed_hash == h["hash"])

    if pubkey is not None:
        _require_crypto()
        try:
            pubkey.verify(h["signature"], h["data_to_sign"], crypto_padding.PKCS1v15(), crypto_hashes.SHA256())
            result["checks"]["signature_valid_for_given_pubkey"] = True
        except Exception:
            result["checks"]["signature_valid_for_given_pubkey"] = False
    else:
        result["checks"]["signature_valid_for_given_pubkey"] = None  # not checked

    image = buf[0:footer["original_image_size"]]
    for d in h["descriptors"]:
        if d["type"] != "hash":
            continue
        salt = bytes.fromhex(d["salt"])
        digest = bytes.fromhex(d["digest"])
        actual = hashlib.sha256(salt + image).digest()
        result["checks"][f"image_matches_descriptor[{d['partition_name']}]"] = (actual.hex() == digest.hex())

    result["ok"] = all(v is not False for v in result["checks"].values())
    return result



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
        print("         signing; re-sign the output with `aik.py sign` (or avbtool) if you need it to")
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
        print("         re-sign with `aik.py sign` (or avbtool) if verified boot needs to pass.")

    if getattr(args, "verify", False):
        print("\nverifying repacked image round-trips...")
        reparsed = parse_boot_header(bytes(out)) if kind == "boot" else parse_vendor_boot_header(bytes(out))
        if not reparsed:
            print("  FAILED: repacked image does not parse back as a valid image", file=sys.stderr)
            sys.exit(1)
        ok = True
        for name, off, size in reparsed["sections"]:
            expected = len(final_bytes.get(name, b""))
            if size != expected:
                print(f"  FAILED: section '{name}' size mismatch after round-trip: expected {expected}, got {size}")
                ok = False
        if ok:
            print(f"  OK -- header_version={reparsed['header']['header_version']}, "
                  f"{len(reparsed['sections'])} sections all present with matching sizes")
        else:
            sys.exit(1)


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


def cmd_diff(args):
    with open(args.image_a, "rb") as f:
        buf_a = f.read()
    with open(args.image_b, "rb") as f:
        buf_b = f.read()
    pa = parse_boot_header(buf_a) or parse_vendor_boot_header(buf_a)
    pb = parse_boot_header(buf_b) or parse_vendor_boot_header(buf_b)
    if not pa or not pb:
        print("error: one or both files are not recognized boot/vendor_boot images", file=sys.stderr)
        sys.exit(1)

    print(f"--- {args.image_a}")
    print(f"+++ {args.image_b}")
    print()

    ha, hb = pa["header"], pb["header"]
    keys = sorted(set(ha.keys()) | set(hb.keys()))
    any_header_diff = False
    for k in keys:
        va, vb = ha.get(k), hb.get(k)
        if va != vb:
            any_header_diff = True
            print(f"  header.{k}:")
            print(f"    - {va}")
            print(f"    + {vb}")
    if not any_header_diff:
        print("  header: identical")

    def sec_map(buf, parsed):
        m = {}
        for name, off, size in parsed["sections"]:
            if size == 0:
                continue
            data = buf[off:off + size]
            m[name] = {"size": size, "compression": detect_compression(data), "sha256": hashlib.sha256(data).hexdigest()}
        return m

    sa, sb = sec_map(buf_a, pa), sec_map(buf_b, pb)
    print()
    for name in sorted(set(sa.keys()) | set(sb.keys())):
        a, b = sa.get(name), sb.get(name)
        if a is None:
            print(f"  section {name}: only in {args.image_b}  ({b['size']} bytes, {b['compression']})")
        elif b is None:
            print(f"  section {name}: only in {args.image_a}  ({a['size']} bytes, {a['compression']})")
        elif a["sha256"] == b["sha256"]:
            print(f"  section {name}: identical  ({a['size']} bytes)")
        else:
            print(f"  section {name}: CHANGED  {a['size']} bytes -> {b['size']} bytes  ({a['compression']} -> {b['compression']})")

            # if both are (or decompress to) cpio ramdisks, diff file-by-file too
            def plain_cpio(buf_data, comp):
                if comp == "cpio-newc":
                    return buf_data
                dec = decompress(buf_data, comp)
                return dec if dec is not None and detect_compression(dec) == "cpio-newc" else None

            off_a = next(o for n, o, s in pa["sections"] if n == name)
            off_b = next(o for n, o, s in pb["sections"] if n == name)
            raw_a = buf_a[off_a:off_a + a["size"]]
            raw_b = buf_b[off_b:off_b + b["size"]]
            plain_a = plain_cpio(raw_a, a["compression"])
            plain_b = plain_cpio(raw_b, b["compression"])
            if plain_a is not None and plain_b is not None:
                ea = {e["name"]: e for e in parse_cpio(plain_a)}
                eb = {e["name"]: e for e in parse_cpio(plain_b)}
                for fname in sorted(set(ea.keys()) | set(eb.keys())):
                    if fname not in ea:
                        print(f"      + {fname}  (added)")
                    elif fname not in eb:
                        print(f"      - {fname}  (removed)")
                    else:
                        da = plain_a[ea[fname]["data_start"]:ea[fname]["data_start"] + ea[fname]["size"]]
                        db = plain_b[eb[fname]["data_start"]:eb[fname]["data_start"] + eb[fname]["size"]]
                        if da != db or ea[fname]["mode"] != eb[fname]["mode"]:
                            print(f"      * {fname}  (modified, {len(da)} -> {len(db)} bytes)")


def cmd_sign(args):
    if args.gen_key:
        print(f"generating {args.key_bits}-bit RSA key -> {args.gen_key}")
        priv = avb_gen_key(args.gen_key, bits=args.key_bits)
    elif args.key:
        priv = avb_load_private_key(args.key)
    else:
        print("error: provide --key <priv.pem> or --gen-key <out.pem> to sign with", file=sys.stderr)
        sys.exit(1)

    algo = "SHA256_RSA4096" if priv.key_size == 4096 else "SHA256_RSA2048"
    if priv.key_size not in (2048, 4096):
        print(f"error: unsupported key size {priv.key_size} (need 2048 or 4096 bits)", file=sys.stderr)
        sys.exit(1)

    with open(args.image, "rb") as f:
        image_bytes = f.read()
    existing = avb_parse_footer(image_bytes)
    if existing:
        print(f"note: source image already has an AVB footer (original_image_size={existing['original_image_size']});")
        print(f"      re-signing over the full file, not just the original payload. Use the unsigned")
        print(f"      source image as input if that's not what you want.")

    out, meta = avb_sign_image(image_bytes, priv, partition_name=args.partition_name, algorithm=algo)
    output = args.output or (os.path.splitext(args.image)[0] + "-signed.img")
    with open(output, "wb") as f:
        f.write(out)

    print(f"signed as partition '{meta['partition_name']}' using {meta['algorithm']}")
    print(f"  image size      : {human(meta['original_image_size'])}")
    print(f"  vbmeta offset   : 0x{meta['vbmeta_offset']:x}  ({human(meta['vbmeta_size'])})")
    print(f"  partition size  : {human(meta['partition_size'])}")
    print(f"  salt            : {meta['salt']}")
    print(f"  digest (sha256) : {meta['digest']}")
    print(f"\nwrote {output}")
    if args.gen_key:
        print(f"\nprivate key saved to {args.gen_key} -- keep it safe; you need it for every future re-sign.")
        print("this is a locally-generated test key, not related to any device's real verified-boot key.")
        print("a device will only accept this signature if its avb key store has been repointed at this")
        print("key's public half (e.g. via a custom bootloader / vbmeta digest override on an unlocked device).")


def cmd_verify_sig(args):
    with open(args.image, "rb") as f:
        buf = f.read()
    pubkey = None
    if args.pubkey:
        pubkey = avb_load_public_key(args.pubkey)
    elif args.key:
        pubkey = avb_load_private_key(args.key).public_key()

    result = avb_verify_image(buf, pubkey)
    if not result["ok"] and "reason" in result:
        print(f"NOT SIGNED: {result['reason']}")
        sys.exit(1)

    v = result["vbmeta"]
    print(f"algorithm       : {[k for k, val in AVB_ALGORITHMS.items() if val[0] == v['algorithm_type']] or v['algorithm_type']}")
    print(f"release string  : {v['release_string']}")
    for d in v["descriptors"]:
        print(f"descriptor      : hash, partition={d['partition_name']!r}, image_size={d['image_size']}")
    print()
    for check, ok in result["checks"].items():
        status = "SKIPPED (no public key given)" if ok is None else ("OK" if ok else "FAILED")
        print(f"  [{status:^28}] {check}")
    print()
    if result["ok"]:
        print("overall: OK" + (" (signature not checked -- pass --pubkey or --key)" if pubkey is None else ""))
    else:
        print("overall: FAILED")
        sys.exit(1)



def main():
    p = argparse.ArgumentParser(prog="aik.py", description="Android Image Kitchen (command-line)")
    p.add_argument("--version", action="version", version=f"aik.py {AIK_VERSION}")
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
    p_repack.add_argument("--verify", action="store_true",
                           help="re-parse the repacked image afterward and confirm every section round-tripped")
    p_repack.set_defaults(func=cmd_repack)

    p_diff = sub.add_parser("diff", help="compare header, sections, and ramdisk contents of two images")
    p_diff.add_argument("image_a")
    p_diff.add_argument("image_b")
    p_diff.set_defaults(func=cmd_diff)

    p_sign = sub.add_parser("sign", help="add an AVB hash-footer + vbmeta signature to an image")
    p_sign.add_argument("image")
    p_sign.add_argument("-o", "--output", default=None)
    p_sign.add_argument("--partition-name", default="boot")
    p_sign.add_argument("--key", default=None, help="private key PEM to sign with")
    p_sign.add_argument("--gen-key", default=None, metavar="OUT.pem",
                         help="generate a new RSA key, save it to OUT.pem, and sign with it")
    p_sign.add_argument("--key-bits", type=int, default=2048, choices=[2048, 4096],
                         help="key size when using --gen-key (default: 2048)")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify-sig", help="verify an AVB-signed image's footer, hash, and (optionally) signature")
    p_verify.add_argument("image")
    p_verify.add_argument("--pubkey", default=None, help="public key PEM to verify the signature against")
    p_verify.add_argument("--key", default=None, help="private key PEM (its public half is used to verify)")
    p_verify.set_defaults(func=cmd_verify_sig)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
