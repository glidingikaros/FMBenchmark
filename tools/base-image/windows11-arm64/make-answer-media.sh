#!/bin/sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 1 ] || { echo "usage: make-answer-media.sh <drivers_dir|\"\"> [output_iso]" >&2; exit 2; }
drivers_dir=$1
out_iso=${2:-"$here/build/answer.iso"}

if [ ! -f "$here/autounattend.xml.pkrtpl" ]; then
  echo "error: autounattend.xml.pkrtpl not found next to this script" >&2
  exit 1
fi
ui_language=${FMB_UI_LANGUAGE:-en-US}

netkvm_src="$drivers_dir/NetKVM/w11/ARM64"
if [ -n "$drivers_dir" ] && [ ! -d "$netkvm_src" ]; then
  echo "error: expected NetKVM ARM64 drivers at: $netkvm_src" >&2
  echo "       point <drivers_dir> at a tree containing NetKVM/w11/ARM64/*.inf" >&2
  exit 1
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/fmb-answer.XXXXXX")
trap 'rm -rf "$stage"' EXIT

sed "s/\${ui_language}/$ui_language/g" "$here/autounattend.xml.pkrtpl" > "$stage/autounattend.xml"
mkdir -p "$stage/scripts"
cp "$here/scripts/"*.ps1 "$stage/scripts/"

if [ -n "$drivers_dir" ]; then
  mkdir -p "$stage/\$WinPEDriver\$/NetKVM/w11/ARM64"
  cp -R "$netkvm_src/." "$stage/\$WinPEDriver\$/NetKVM/w11/ARM64/"
fi

mkdir -p "$(dirname "$out_iso")"
rm -f "$out_iso"

hdiutil makehybrid -o "$out_iso" \
  -iso -joliet -udf \
  -default-volume-name FMBANSWER \
  -joliet-volume-name FMBANSWER \
  -udf-volume-name FMBANSWER \
  "$stage"

echo "answer media written: $out_iso"
