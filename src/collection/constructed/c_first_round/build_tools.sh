#!/usr/bin/env bash
#
# build_tools.sh - Compile the wrappers around tools already on the guest.
#
# These matter for a reason the matrix binaries do not: nothing here is
# written for the experiment. 7-Zip appeared in 681 of the ransomware
# analyses and Adobe in 694, so the guest genuinely has them, and cipher,
# compact, robocopy, certutil, findstr, takeown and Defender ship with
# Windows. A detector that fires on these is producing a false positive on
# software an administrator runs on purpose.
#
# Usage:
#   ./build_tools.sh [output_dir]

set -euo pipefail
OUT="${1:-./dist}"
SRC="$(dirname "$0")/hardneg_tools.c"
CC=x86_64-w64-mingw32-gcc

command -v "$CC" >/dev/null 2>&1 || {
    echo "[!] $CC not found: sudo apt-get install -y mingw-w64"; exit 1; }
[ -f "$SRC" ] || { echo "[!] $SRC not found"; exit 1; }
mkdir -p "$OUT"

build() {
    local n="$1" name="$2" note="$3"
    "$CC" -O2 -DTOOL="$n" -o "$OUT/$name.exe" "$SRC" 2>/dev/null
    printf "  %-24s %s\n" "$name.exe" "$note"
}

echo "indistinguishable from encryption at the filesystem level"
build 1  tool_7z_delete    "7z encrypted archive, originals deleted"
build 3  tool_7z_perfile   "7z one container per file, original deleted"
build 4  tool_cipher       "cipher /e -- EFS in place, Microsoft signed"
build 5  tool_compact      "compact /c -- every byte rewritten in place"
build 7  tool_robocopy_mv  "robocopy /MOVE -- source tree emptied"
build 15 tool_shell_rename "for /r ... ren -- rename the whole tree"

echo
echo "same volume, nothing destroyed -- the controls"
build 2  tool_7z_keep      "7z encrypted archive, originals kept"
build 6  tool_robocopy_cp  "robocopy /E -- copy the tree"
build 9  tool_findstr      "findstr /s -- read everything, write nothing"
build 10 tool_defender     "Defender scan -- opens every file, changes none"
build 14 tool_xcopy        "xcopy /E -- a third way to copy a tree"

echo
echo "content or metadata changed by a signed Windows binary"
build 8  tool_certutil     "certutil -encode -- contents replaced per file"
build 11 tool_ps_zip       "PowerShell Compress-Archive"
build 12 tool_attrib       "attrib +h -- metadata only"
build 13 tool_acl          "takeown and icacls across the tree"

echo
echo "ordinary machine activity"
build 16 tool_chrome       "Chrome headless"
build 17 tool_apps         "notepad, mspaint, 7zFM, calc"
build 18 tool_backup       "robocopy then prune -- read, write and delete"

echo
echo "opening the decoy documents in the applications installed to handle them"
echo "  each ends with taskkill, the same call a family makes to release the"
echo "  locks those applications hold -- so the process trail matches and only"
echo "  the reason differs"
build 19 tool_open_docs   "open pdf, docx, xlsx through their handlers"
build 20 tool_acrobat     "Acrobat by path on the decoy PDFs"
build 21 tool_media       "images and media through their handlers"
build 22 tool_session     "three rounds of open, read, close"
build 24 tool_ie_wmp      "Internet Explorer and Media Player on local files"

echo
echo "process termination on its own"
build 23 tool_taskkill    "kill lock holders and stop services, nothing else"

echo
echo "Sysinternals with arguments -- the tools do nothing without them"
echo "  Staged alongside these wrappers, which invoke them against the decoy"
echo "  set. Every one is signed by Microsoft, and sdelete in particular does"
echo "  what m7_wipe was written to imitate: overwrite the contents, then"
echo "  remove the file."
build 25 tool_sdelete     "sdelete -p 2 on the decoy documents"
build 26 tool_du          "du across the whole profile"
build 27 tool_accesschk   "accesschk reads every security descriptor"
build 28 tool_streams     "streams and sigcheck walk the tree"
build 29 tool_autoruns    "autorunsc and handle enumerate everything"
build 30 tool_pskill      "pskill stops the processes holding locks"
build 31 tool_contig      "Contig rewrites each file in place -- AvosLocker's trail"
build 32 tool_strings     "strings reads every byte, writes nothing"
build 33 tool_ru          "ru walks the registry recursively"

echo
n=$(ls -1 "$OUT"/tool_*.exe 2>/dev/null | wc -l)
echo "built $n tool wrappers into $OUT"
echo
for f in "$OUT"/tool_*.exe; do
    printf "  %-24s %s\n" "$(basename "$f")" "$(sha256sum "$f" | cut -c1-24)"
done

cat <<'EOF'

What to look for
----------------
tool_cipher and tool_compact are the sharpest test available. Both are
Microsoft-signed, both rewrite every byte of every document in place, and
neither renames or deletes anything. If the verdict logic calls either of
them encryption, then in-place rewriting alone is sufficient to be
classified as ransomware, and every disk utility on Windows is a false
positive waiting to happen.

tool_7z_perfile is the other end: a legitimate tool producing a one-to-one
mapping where each output is named after its input with a suffix, each is
the size of its input, and each original is gone. That is the shape of
Cuba, of Clop, of most of the sample set. If this is not detected, the
detection is resting on something other than file operations, which is the
claim worth being able to make.

tool_findstr and tool_defender read as much as anything in the ransomware
set and destroy nothing, so any feature that separates them from encryption
is not counting activity.
EOF
