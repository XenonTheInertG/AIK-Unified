#!/usr/bin/env bash
#
# aik.sh -- Android Image Kitchen (shell wrapper)   v1.1.0
#
# Convenience wrapper around aik.py providing the familiar
# unpack/repack workflow, with a default working directory
# so you don't have to pass -o / paths around by hand.
#
# Usage:
#   ./aik.sh unpack  <image> [workdir]       default workdir: ./aik-work
#   ./aik.sh repack  [workdir] [output.img]  default workdir: ./aik-work
#   ./aik.sh info    <image>
#   ./aik.sh diff    <image_a> <image_b>
#   ./aik.sh sign    <image> [output.img] [--gen-key out.pem | --key priv.pem]
#   ./aik.sh verify  <image> [--key priv.pem | --pubkey pub.pem]
#   ./aik.sh clean   [workdir]               remove the working directory
#
#   ./aik.sh batch-unpack <dir-of-images> [workdir-root]
#       unpacks every *.img in <dir-of-images> into workdir-root/<name>/
#       default workdir-root: ./aik-batch
#
#   ./aik.sh batch-repack [workdir-root] [output-dir]
#       repacks every unpacked subdir under workdir-root
#       default workdir-root: ./aik-batch, default output-dir: ./aik-batch-out
#
#   ./aik.sh --version
#
# Requires: python3 on PATH, and aik.py in the same directory as this
# script (or set AIK_PY to point at it explicitly).
#
# Config file: on startup, sources ./.aikrc then ~/.aikrc if present
# (later one wins). Recognized variables: AIK_PY, DEFAULT_WORKDIR,
# DEFAULT_BATCH_ROOT, DEFAULT_BATCH_OUT.
#
set -euo pipefail

AIK_SH_VERSION="1.1.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
AIK_PY="${AIK_PY:-$SCRIPT_DIR/aik.py}"
DEFAULT_WORKDIR="./aik-work"
DEFAULT_BATCH_ROOT="./aik-batch"
DEFAULT_BATCH_OUT="./aik-batch-out"

# --- config file: project-local .aikrc, then user-global ~/.aikrc ---
for rc in "./.aikrc" "$HOME/.aikrc"; do
  if [ -f "$rc" ]; then
    # shellcheck disable=SC1090
    source "$rc"
  fi
done

usage() {
  sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

require_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found on PATH" >&2
    exit 1
  fi
  if [ ! -f "$AIK_PY" ]; then
    echo "error: aik.py not found at $AIK_PY" >&2
    echo "       place aik.py next to this script, set AIK_PY=/path/to/aik.py," >&2
    echo "       or set AIK_PY in ./.aikrc / ~/.aikrc" >&2
    exit 1
  fi
}

confirm_overwrite_dir() {
  local dir="$1"
  if [ -d "$dir" ]; then
    echo "'$dir' already exists -- contents will be overwritten where they overlap."
    read -r -p "continue? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted."; exit 1; }
  fi
}

cmd_unpack() {
  local image="${1:?usage: aik.sh unpack <image> [workdir]}"
  local workdir="${2:-$DEFAULT_WORKDIR}"
  [ -f "$image" ] || { echo "error: image not found: $image" >&2; exit 1; }
  confirm_overwrite_dir "$workdir"
  echo "==> unpacking $image into $workdir"
  python3 "$AIK_PY" unpack "$image" -o "$workdir"
  echo
  echo "==> done. edit files under '$workdir' (kernel.bin, *-extracted/ ramdisk trees), then run:"
  echo "      ./aik.sh repack $workdir <output.img>"
}

cmd_repack() {
  local workdir="${1:-$DEFAULT_WORKDIR}"
  local output="${2:-repacked.img}"
  if [ ! -f "$workdir/bootimg.json" ]; then
    echo "error: '$workdir' doesn't look like an aik.py unpack output (no bootimg.json)" >&2
    exit 1
  fi
  echo "==> repacking $workdir into $output"
  python3 "$AIK_PY" repack "$workdir" -o "$output" --verify
  echo
  echo "==> wrote $output"
}

cmd_info() {
  local image="${1:?usage: aik.sh info <image>}"
  [ -f "$image" ] || { echo "error: image not found: $image" >&2; exit 1; }
  python3 "$AIK_PY" info "$image"
}

cmd_diff() {
  local a="${1:?usage: aik.sh diff <image_a> <image_b>}"
  local b="${2:?usage: aik.sh diff <image_a> <image_b>}"
  [ -f "$a" ] || { echo "error: image not found: $a" >&2; exit 1; }
  [ -f "$b" ] || { echo "error: image not found: $b" >&2; exit 1; }
  python3 "$AIK_PY" diff "$a" "$b"
}

cmd_sign() {
  local image="${1:?usage: aik.sh sign <image> [output.img] [-- aik.py sign options]}"
  shift
  local output="repacked-signed.img"
  if [ "${1:-}" ] && [[ "${1:-}" != --* ]]; then
    output="$1"
    shift
  fi
  [ -f "$image" ] || { echo "error: image not found: $image" >&2; exit 1; }
  echo "==> signing $image -> $output"
  python3 "$AIK_PY" sign "$image" -o "$output" "$@"
}

cmd_verify() {
  local image="${1:?usage: aik.sh verify <image> [-- aik.py verify-sig options]}"
  shift
  [ -f "$image" ] || { echo "error: image not found: $image" >&2; exit 1; }
  python3 "$AIK_PY" verify-sig "$image" "$@"
}

cmd_clean() {
  local workdir="${1:-$DEFAULT_WORKDIR}"
  if [ ! -d "$workdir" ]; then
    echo "nothing to clean: '$workdir' does not exist"
    return
  fi
  read -r -p "remove '$workdir'? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted."; exit 1; }
  rm -rf -- "$workdir"
  echo "removed $workdir"
}

cmd_batch_unpack() {
  local srcdir="${1:?usage: aik.sh batch-unpack <dir-of-images> [workdir-root]}"
  local root="${2:-$DEFAULT_BATCH_ROOT}"
  [ -d "$srcdir" ] || { echo "error: not a directory: $srcdir" >&2; exit 1; }
  shopt -s nullglob
  local images=("$srcdir"/*.img)
  shopt -u nullglob
  if [ ${#images[@]} -eq 0 ]; then
    echo "no *.img files found in $srcdir"
    exit 1
  fi
  mkdir -p "$root"
  local ok=0 fail=0
  for img in "${images[@]}"; do
    local name
    name="$(basename "$img" .img)"
    echo "==> [$name] unpacking..."
    if python3 "$AIK_PY" unpack "$img" -o "$root/$name" >/dev/null 2>"$root/$name.unpack.err"; then
      rm -f "$root/$name.unpack.err"
      ok=$((ok + 1))
    else
      echo "    FAILED -- see $root/$name.unpack.err"
      fail=$((fail + 1))
    fi
  done
  echo
  echo "==> batch unpack complete: $ok ok, $fail failed. workdirs under $root/"
}

cmd_batch_repack() {
  local root="${1:-$DEFAULT_BATCH_ROOT}"
  local outdir="${2:-$DEFAULT_BATCH_OUT}"
  [ -d "$root" ] || { echo "error: not a directory: $root" >&2; exit 1; }
  mkdir -p "$outdir"
  local ok=0 fail=0
  for workdir in "$root"/*/; do
    [ -f "$workdir/bootimg.json" ] || continue
    local name
    name="$(basename "$workdir")"
    local out="$outdir/$name-repacked.img"
    echo "==> [$name] repacking..."
    if python3 "$AIK_PY" repack "$workdir" -o "$out" --verify >"$outdir/$name.repack.log" 2>&1; then
      ok=$((ok + 1))
    else
      echo "    FAILED -- see $outdir/$name.repack.log"
      fail=$((fail + 1))
    fi
  done
  echo
  echo "==> batch repack complete: $ok ok, $fail failed. images under $outdir/"
}

main() {
  local sub="${1:-}"
  if [ "$sub" = "--version" ] || [ "$sub" = "-v" ]; then
    echo "aik.sh $AIK_SH_VERSION"
    exit 0
  fi
  require_python
  [ -n "$sub" ] || usage
  shift || true
  case "$sub" in
    unpack)         cmd_unpack "$@" ;;
    repack)         cmd_repack "$@" ;;
    info)           cmd_info "$@" ;;
    diff)           cmd_diff "$@" ;;
    sign)           cmd_sign "$@" ;;
    verify)         cmd_verify "$@" ;;
    clean)          cmd_clean "$@" ;;
    batch-unpack)   cmd_batch_unpack "$@" ;;
    batch-repack)   cmd_batch_repack "$@" ;;
    -h|--help|help) usage ;;
    *) echo "error: unknown subcommand '$sub'" >&2; usage ;;
  esac
}

main "$@"
