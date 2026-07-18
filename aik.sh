#!/usr/bin/env bash
#
# aik.sh -- Android Image Kitchen (shell wrapper)
#
# Convenience wrapper around aik.py providing the familiar
# unpack/repack workflow, with a default working directory
# so you don't have to pass -o / paths around by hand.
#
# Usage:
#   ./aik.sh unpack <image> [workdir]      default workdir: ./aik-work
#   ./aik.sh repack [workdir] [output.img] default workdir: ./aik-work
#   ./aik.sh info   <image>
#   ./aik.sh clean  [workdir]              remove the working directory
#
# Requires: python3 on PATH, and aik.py in the same directory as this
# script (or set AIK_PY to point at it explicitly).
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
AIK_PY="${AIK_PY:-$SCRIPT_DIR/aik.py}"
DEFAULT_WORKDIR="./aik-work"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

require_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found on PATH" >&2
    exit 1
  fi
  if [ ! -f "$AIK_PY" ]; then
    echo "error: aik.py not found at $AIK_PY" >&2
    echo "       place aik.py next to this script, or set AIK_PY=/path/to/aik.py" >&2
    exit 1
  fi
}

cmd_unpack() {
  local image="${1:?usage: aik.sh unpack <image> [workdir]}"
  local workdir="${2:-$DEFAULT_WORKDIR}"
  if [ ! -f "$image" ]; then
    echo "error: image not found: $image" >&2
    exit 1
  fi
  if [ -d "$workdir" ]; then
    echo "workdir '$workdir' already exists -- contents will be overwritten where they overlap."
    read -r -p "continue? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted."; exit 1; }
  fi
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
  python3 "$AIK_PY" repack "$workdir" -o "$output"
  echo
  echo "==> wrote $output"
}

cmd_info() {
  local image="${1:?usage: aik.sh info <image>}"
  if [ ! -f "$image" ]; then
    echo "error: image not found: $image" >&2
    exit 1
  fi
  python3 "$AIK_PY" info "$image"
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

main() {
  require_python
  local sub="${1:-}"
  [ -n "$sub" ] || usage
  shift || true
  case "$sub" in
    unpack) cmd_unpack "$@" ;;
    repack) cmd_repack "$@" ;;
    info)   cmd_info "$@" ;;
    clean)  cmd_clean "$@" ;;
    -h|--help|help) usage ;;
    *) echo "error: unknown subcommand '$sub'" >&2; usage ;;
  esac
}

main "$@"
