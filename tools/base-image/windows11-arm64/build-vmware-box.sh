#!/bin/sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
iso=${1:?"usage: build-vmware-box.sh <windows-11-arm64.iso> <sha256>"}
sha=$(printf '%s' "${2:?"usage: build-vmware-box.sh <windows-11-arm64.iso> <sha256>"}" | tr 'A-F' 'a-f')
box_name=fmb/windows-11-arm64
template="$here/windows11-arm64-vmware.pkr.hcl"
work=${FMB_BASE_BUILD_DIR:-$here}
box_file="$work/output/fmb-windows-11-arm64-vmware.box"
tools_iso="/Applications/VMware Fusion.app/Contents/Library/isoimages/arm64/windows.iso"

fail() { echo "error: $*" >&2; exit 1; }

iso_ui_language() {
  mnt=$(mktemp -d "${TMPDIR:-/tmp}/fmb-iso.XXXXXX")
  hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mnt" "$1" >/dev/null 2>&1 || { rmdir "$mnt"; return 1; }
  tag=$(tr -d '\r' < "$mnt/sources/lang.ini" |
    awk '/^\[Available UI Languages\]/ {on=1; next} /^\[/ {on=0} on && NF {print $1; exit}')
  hdiutil detach "$mnt" >/dev/null 2>&1; rmdir "$mnt"
  printf '%s' "$tag" | awk -F- 'NF==2 {print tolower($1) "-" toupper($2); next} {print}'
}

[ "$(uname -s)/$(uname -m)" = "Darwin/arm64" ] || fail "this build needs an Apple Silicon Mac"
command -v packer >/dev/null 2>&1 || fail "Packer is not installed (https://developer.hashicorp.com/packer/install)"
command -v vagrant >/dev/null 2>&1 || fail "Vagrant is not installed (https://developer.hashicorp.com/vagrant/install)"
[ -f "$tools_iso" ] || fail "VMware Fusion 13 with its Windows ARM tools is not installed ($tools_iso)"
vagrant plugin list | grep -q '^vagrant-vmware-desktop ' || fail "run: vagrant plugin install vagrant-vmware-desktop"
[ -f "$iso" ] || fail "ISO not found: $iso"
if vagrant box list | grep -q "^$box_name "; then
  fail "a box named $box_name is already installed; remove it (vagrant box remove $box_name) or set VAGRANT_HOME to another folder"
fi
mkdir -p "$work"
[ ! -e "$work/output" ] || fail "remove the previous build output first: $work/output"
free_gb=$(df -g "$work" | awk 'NR==2 {print $4}')
[ "$free_gb" -ge 60 ] || fail "the build needs about 60 GB free in $work; $free_gb GB available (set FMB_BASE_BUILD_DIR)"

echo "Checking the ISO's SHA-256 ..."
actual=$(shasum -a 256 "$iso" | awk '{print $1}')
[ "$actual" = "$sha" ] || fail "ISO SHA-256 is $actual, not the expected $sha"
ui_language=${FMB_UI_LANGUAGE:-$(iso_ui_language "$iso")} || fail "cannot read the ISO's UI language (set FMB_UI_LANGUAGE)"
[ -n "$ui_language" ] || fail "the ISO lists no UI language (set FMB_UI_LANGUAGE)"
echo "Installing with UI language $ui_language; the user locale stays en-US."

mkdir -p "$work/build"
FMB_UI_LANGUAGE=$ui_language "$here/make-answer-media.sh" "" "$work/build/answer.iso"
packer init "$template"
rtc_bias_minutes=480
rtc_start=$(( $(date +%s) - rtc_bias_minutes * 60 ))
set -- -var "iso_path=$iso" -var "iso_sha256=$sha" -var "work_dir=$work" -var "answer_iso=$work/build/answer.iso" -var "rtc_start_time=$rtc_start"
packer validate "$@" "$template"
packer build -on-error=abort "$@" "$template" ||
  fail "the build failed; its VM is kept in $work/output/vmware. Stop it (vmrun -T fusion stop '$work/output/vmware/box.vmx' hard) and delete $work/output before retrying"

vagrant box add --name "$box_name" "$box_file"
build=$(tr -d '\r\n ' < "$work/build/guest-build.txt")
echo
echo "Added $box_name (Windows build $build). Next, from the package directory:"
echo "  fmb paper generate --check-host"
echo "  fmb paper generate --write-dependency-lock ~/fmb/dependency-lock.json --guest-windows-build $build"
echo "The box file $box_file can be deleted once added."
