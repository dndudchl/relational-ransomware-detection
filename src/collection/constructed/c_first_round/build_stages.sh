#!/usr/bin/env bash
#
# build_stages.sh - Cross-compile the seven staged binaries from Linux.
#
# mingw is used rather than PyInstaller because a PyInstaller executable
# unpacks a Python runtime into %TEMP% before it does anything, which is
# several hundred file writes of its own. One analysis in the ransomware set
# was nearly recorded as encryption on that basis alone. A C binary starts
# and does only what it was told to.
#
# Each stage is its own binary. Switching behaviour with a runtime flag would
# give all seven the same hash -- so the feature table would carry the same
# sha256 seven times, on top of the 91 duplicates already there -- and the
# same import table, when the difference in what each stage needs to import
# is part of what is being measured.
#
# Usage:
#   ./build_stages.sh [output_dir]

set -euo pipefail
OUT="${1:-./dist}"
SRC="$(dirname "$0")/hardneg_stages.c"
CC=x86_64-w64-mingw32-gcc

command -v "$CC" >/dev/null 2>&1 || {
    echo "[!] $CC not found. Install it with:"
    echo "      sudo apt-get install -y mingw-w64"
    exit 1
}
[ -f "$SRC" ] || { echo "[!] $SRC not found"; exit 1; }

mkdir -p "$OUT"

DESC=(
    ""
    "enumerate and read                     a scanner"
    "+ write each file back in place        an editor, cipher /e"
    "+ delete the original after writing    an archiver with -sdel"
    "+ rename onto one new extension        a migration script"
    "+ drop the same note in every folder   a licence tool"
    "+ change the wallpaper                 a theme installer"
    "+ remove shadow copies                 disk cleanup"
)

echo "building seven stages into $OUT"
echo
for n in 1 2 3 4 5 6 7; do
    "$CC" -O2 -DSTAGES="$n" -o "$OUT/stage$n.exe" "$SRC" 2>/dev/null
    printf "  stage%d.exe  %s\n" "$n" "${DESC[$n]}"
done

echo
echo "hashes -- each stage is a distinct binary, so each gets its own row"
for n in 1 2 3 4 5 6 7; do
    printf "  stage%d  %s\n" "$n" "$(sha256sum "$OUT/stage$n.exe" | cut -c1-32)"
done

echo
echo "imports that appear as the stages accumulate"
if command -v x86_64-w64-mingw32-objdump >/dev/null 2>&1; then
    prev=""
    for n in 1 2 3 4 5 6 7; do
        now=$(x86_64-w64-mingw32-objdump -p "$OUT/stage$n.exe" 2>/dev/null \
              | grep -oP '^\s+\K[A-Za-z]+[AW]?$' | sort -u | tr '\n' ' ')
        if [ -z "$prev" ]; then
            printf "  stage%d  %s\n" "$n" "$(echo "$now" | tr ' ' '\n' | grep -c .) imports"
        else
            added=$(comm -13 <(echo "$prev" | tr ' ' '\n' | sort -u) \
                             <(echo "$now"  | tr ' ' '\n' | sort -u) | tr '\n' ' ')
            printf "  stage%d  new: %s\n" "$n" "${added:-none}"
        fi
        prev="$now"
    done
fi

cat <<'EOF'

Next:
  Copy the seven executables to each analysis host and submit them the same
  way every ransomware sample was submitted -- same machine, same route,
  same 600 second timeout. Anything else and the timing features are not
  comparable.

    for n in 1 2 3 4 5 6 7; do
      for rep in 1 2 3 4 5; do
        sudo -u cape /etc/poetry/bin/poetry run python3 utils/submit.py \
          --machine cuckoo1 --route internet --timeout 600 \
          /var/tmp/cape_staging/stage$n.exe
      done
    done

  Five runs each gives 35 analyses and enough repetition to tell a stage
  that reliably trips the detector from one that trips it occasionally.

  The number to read afterwards is the lowest stage that reaches
  TRUE_ENCRYPTION. If that is stage 3, file operations alone are sufficient
  and the corroboration rule is not doing its job. If nothing fires until 5
  or 6, the combination is carrying the decision, which is what the thesis
  claims.
EOF
