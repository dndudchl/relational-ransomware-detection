#!/usr/bin/env bash
#
# build_matrix.sh - Compile the designed variant set.
#
# Not a full factorial. Every variant differs from one baseline in exactly
# one respect, because that is what makes a feature's response attributable:
# if only the method changed and only chain_read_destroy moved, then
# chain_read_destroy was measuring the method.
#
# The baseline is the shape most ransomware in the sample set produces --
# read each decoy, write a replacement, remove the original, all at once,
# with no side behaviour. Each group below moves one factor off it.
#
# Usage:
#   ./build_matrix.sh [output_dir]

set -euo pipefail
OUT="${1:-./dist}"
SRC="$(dirname "$0")/hardneg_matrix.c"
CC=x86_64-w64-mingw32-gcc

command -v "$CC" >/dev/null 2>&1 || {
    echo "[!] $CC not found: sudo apt-get install -y mingw-w64"; exit 1; }
[ -f "$SRC" ] || { echo "[!] $SRC not found"; exit 1; }
mkdir -p "$OUT"

built=0
build() {
    local name="$1"; shift
    local note="$1"; shift
    "$CC" -O2 "$@" -o "$OUT/$name.exe" "$SRC" 2>/dev/null
    printf "  %-22s %s\n" "$name.exe" "$note"
    built=$((built + 1))
}

echo "baseline: read a decoy, write a replacement, delete the original,"
echo "          all at once, no side behaviour"
echo

echo "method -- same files, different relation between what is read and written"
build m1_inplace   "overwrite in place        an editor, cipher /e" -DMETHOD=1
build m2_copydel   "copy then delete          7z -sdel   [BASELINE]" -DMETHOD=2
build m3_rename    "rename only               a bulk rename tool"    -DMETHOD=3
build m4_manytoone "many files, one output    a real archiver"       -DMETHOD=4
build m5_drop      "write files never read    a dropper, installer"  -DMETHOD=5

echo
echo "scope -- the two places real runs actually end up"
build s1_decoys    "user profile only         reaches the decoys"     -DSCOPE=1
build s2_progfiles "Program Files only        where task 1405 spent its ten minutes" -DSCOPE=2
build s3_walkroot  "alphabetical from C:\\     never reaches the profile" -DSCOPE=3

echo
echo "volume -- identical behaviour, different amount"
build v010 "10 files"   -DLIMIT=10
build v050 "50 files"   -DLIMIT=50
build v100 "100 files"  -DLIMIT=100
build v200 "200 files"  -DLIMIT=200
build v999 "no limit"   -DLIMIT=0

echo
echo "selectivity -- executables live in Program Files, not among the decoys"
build f1_documents  "documents only"                 -DFILTER=1
build f2_media      "media only"                     -DFILTER=2
build f3_executable "executables only, Program Files" -DFILTER=3 -DSCOPE=2
build f0_all        "every type, Program Files"       -DFILTER=0 -DSCOPE=2

echo
echo "timing -- the same work spread differently across the window"
build t0_burst  "as fast as possible"        -DTIMING=0
build t1_spread "evenly over eight minutes"  -DTIMING=1
build t2_batch  "bursts of twenty, then wait" -DTIMING=2

echo
echo "side behaviour alone -- no file transformation at all"
echo "  a run that only does one of these should not be called encryption"
build e1_note_only      "drops a note in every directory" -DFILES_ONLY=0 -DEFFECTS=1
build e2_wallpaper_only "changes the wallpaper"           -DFILES_ONLY=0 -DEFFECTS=2
build e4_shadow_only    "removes shadow copies"           -DFILES_ONLY=0 -DEFFECTS=4
build e28_prep_only     "shadow, recovery and service"    -DFILES_ONLY=0 -DEFFECTS=28

echo
echo "encryption itself -- m6 differs from the baseline in one step and no other"
echo "  m2 reads, writes, deletes.  m6 reads, encrypts, writes, deletes."
echo "  Nothing else about them differs, so a feature that separates the two"
echo "  is seeing the cryptography and one that does not is seeing the files."
build m6_crypto  "read, CryptEncrypt, write, delete   [E]"        -DMETHOD=6
build m2_nocrypt "the same without the encryption     [F, = m2]"  -DMETHOD=2

echo
echo "destruction without cryptography"
build m7_wipe    "overwrite with random, then delete   sdelete, a wiper" -DMETHOD=7
build m8_keep    "copy and keep the original           non-destructive"  -DMETHOD=8
build m9_move    "move to another directory            name survives"    -DMETHOD=9

echo
echo "naming -- one family renamed 4,908 files this way and registered"
echo "          nothing on the append check"
build r1_replace_name "discard the original name entirely" -DMETHOD=2 -DRENAME_MODE=1
build r1_rename_only  "rename only, name discarded"        -DMETHOD=3 -DRENAME_MODE=1

echo
echo "ordering -- same counts, no interleaving"
build b1_batch "read every file, then write every file" -DBATCH=1

echo
echo "generated targets -- volume without the confound that reaching more"
echo "  decoys also means reaching more directories and more file types"
build g0100 "100 files it made itself"  -DGENERATE=100
build g0500 "500 files it made itself"  -DGENERATE=500
build g1500 "1500 files it made itself" -DGENERATE=1500

echo
echo "wide scope, nothing destroyed"
build w_progfiles_read "read Program Files, write nothing" -DSCOPE=2 -DMETHOD=8

echo
echo "combined -- the baseline plus everything, the closest thing here to"
echo "            actual ransomware without any encryption"
build x_full "copy+delete, note, wallpaper, shadow, recovery, service" \
    -DMETHOD=2 -DEFFECTS=31

echo
echo "built $built binaries into $OUT"
echo
echo "hashes"
for f in "$OUT"/*.exe; do
    printf "  %-22s %s\n" "$(basename "$f")" "$(sha256sum "$f" | cut -c1-24)"
done

cat <<'EOF'

Submitting
----------
Same machine, route and timeout as every ransomware sample, or the timing
features are not comparable:

  for f in /var/tmp/cape_staging/*.exe; do
    for rep in 1 2 3; do
      sudo -u cape /etc/poetry/bin/poetry run python3 utils/submit.py \
        --machine cuckoo1 --route internet --timeout 600 "$f"
    done
  done

Three runs each. These are deterministic, so repetition is there to catch a
variant that lands near a threshold and falls on different sides of it,
not to average out noise.

Reading the result
------------------
  e*_only          any of these reaching TRUE_ENCRYPTION is a defect: the
                   corroboration rule exists to stop exactly that
  m3_rename        renaming without touching contents. If this is called
                   encryption, the rename axis is deciding on its own
  m4_manytoone     the archiver shape. rw_size_ratio should separate it from
                   m2 even though both read the same files and delete them
  v010..v999       whichever features track this line were counting volume
  s2/s3            comparable to the runs that never reached the decoys
EOF
