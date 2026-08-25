#!/usr/bin/env python3
"""
classify_failures.py - Sort the hard negatives the model flagged into the
reasons it flagged them.

Why the count alone is not the finding
--------------------------------------
"Forty-four of sixty-eight programs were classified as ransomware" says the
detector fails on active software. It does not say what kind of failure that
is, and the sixty-eight do not fail the same way. Three quite different
things are being counted together:

  the detector is right
      m2_copydel reads every document, writes a replacement and removes the
      original. The user's files are gone. Calling that ransomware is not a
      false positive, it is the correct answer to a program that behaves this
      way, and no feature should separate it -- 7z -sdel does exactly this on
      purpose, which is the point.

  the behaviour is genuinely ambiguous
      cipher /e and an editor saving a file produce the same trail: read the
      path, write the path. Consent is the only difference and consent leaves
      no trace in a sandbox. A detector that separated these would be reading
      something other than behaviour.

  the detector cannot see it at all
      cipher /e and compact /c rewrite every byte of every document through
      the filesystem driver, so no userland file event is recorded. The most
      complete destruction in the set is also the least visible, and no
      amount of feature engineering on file events reaches it.

Only the second group is a research problem. The first is correct behaviour
and the third is an instrumentation limit. Reporting them as one number
overstates the failure and hides where the work would have to go.

Usage
-----
  python3 classify_failures.py --scores /tmp/hardneg_scores.csv \\
      --map ~/hardneg_map.csv --verdicts /tmp/v2_hn.csv \\
      --relational /tmp/rel_all.csv
"""

import os
import csv
import argparse
from collections import defaultdict

# What each variant does to files that were already there. Assigned from the
# source, not from the outcome, so the categories do not move with the result.
#
#   destroys   the originals are gone or replaced. A detector is supposed to
#              fire on these.
#   ambiguous  the file trail is the same as encryption but the act is one a
#              person asked for.
#   invisible  the contents are destroyed through a path the sandbox does not
#              record.
#   harmless   nothing that existed was touched.
INTENT = {
    # --- destroys what was there ---------------------------------------
    "m2_copydel":      ("destroys", "copy then delete, the 7z -sdel shape"),
    # The same binary as m2_copydel, built under a second name so that the
    # pair m6_crypto / m2_nocrypt differs in one step and nothing else.
    "m2_nocrypt":      ("destroys", "copy then delete, no encryption [F of the pair]"),
    "m4_manytoone":    ("destroys", "many inputs folded into one, sources removed"),
    "m6_crypto":       ("destroys", "encrypts, then removes the original"),
    "m7_wipe":         ("destroys", "overwrites with random, then removes"),
    "m9_move":         ("destroys", "relocates every file out of its folder"),
    "r1_replace_name": ("destroys", "copy then delete, original name discarded"),
    "r1_rename_only":  ("destroys", "renamed away, original name discarded"),
    "m3_rename":       ("destroys", "renamed, contents untouched"),
    "b1_batch":        ("destroys", "copy then delete, read phase separated"),
    "t0_burst":        ("destroys", "copy then delete, as fast as possible"),
    "t1_spread":       ("destroys", "copy then delete, spread over the window"),
    "t2_batch":        ("destroys", "copy then delete, in bursts"),
    "s1_decoys":       ("destroys", "copy then delete, user profile only"),
    "s2_progfiles":    ("destroys", "copy then delete, Program Files"),
    "s3_walkroot":     ("destroys", "copy then delete, from the root"),
    "f0_all":          ("destroys", "copy then delete, every file type"),
    "f1_documents":    ("destroys", "copy then delete, documents only"),
    "f2_media":        ("destroys", "copy then delete, media only"),
    "f3_executable":   ("destroys", "copy then delete, executables only"),
    "v010":            ("destroys", "ten files"),
    "v050":            ("destroys", "fifty files"),
    "v100":            ("destroys", "a hundred files"),
    "v200":            ("destroys", "two hundred files"),
    "v999":            ("destroys", "every file found"),
    "g0100":           ("destroys", "a hundred files it generated"),
    "g0500":           ("destroys", "five hundred files it generated"),
    "g1500":           ("destroys", "fifteen hundred files it generated"),
    "x_full":          ("destroys", "copy and delete plus every side behaviour"),
    "stage3":          ("destroys", "adds deletion of the original"),
    "stage4":          ("destroys", "adds a shared new extension"),
    "stage5":          ("destroys", "adds a note in every folder"),
    "stage6":          ("destroys", "adds the wallpaper"),
    "stage7":          ("destroys", "adds shadow copy removal"),
    "tool_7z_delete":  ("destroys", "7-Zip archive, sources deleted"),
    "tool_7z_perfile": ("destroys", "7-Zip one container per file, original deleted"),
    "tool_robocopy_mv":("destroys", "robocopy /MOVE empties the source tree"),
    "tool_shell_rename":("destroys", "shell rename across the tree"),
    "tool_backup":     ("destroys", "backup then prune"),

    # --- same trail as encryption, different reason --------------------
    "stage2":          ("ambiguous", "overwrite in place: an editor saving a file"),
    "m1_inplace":      ("ambiguous", "overwrite in place"),
    "tool_certutil":   ("ambiguous", "contents replaced per file by a signed binary"),

    # --- destroyed but unrecorded --------------------------------------
    "tool_cipher":     ("invisible", "EFS: every byte replaced, no file event"),
    "tool_compact":    ("invisible", "NTFS compression: rewritten in place, no event"),

    # --- touched nothing that existed -----------------------------------
    "stage1":          ("harmless", "enumerate and read"),
    "m5_drop":         ("harmless", "writes new files, reads nothing"),
    "m8_keep":         ("harmless", "copies beside the original, which stays"),
    "w_progfiles_read":("harmless", "reads Program Files, writes nothing"),
    "e1_note_only":    ("harmless", "a note in every folder, no file touched"),
    "e2_wallpaper_only":("harmless", "changes the wallpaper"),
    "e4_shadow_only":  ("harmless", "removes shadow copies"),
    "e28_prep_only":   ("harmless", "shadow, recovery and services"),
    "tool_7z_keep":    ("harmless", "7-Zip archive, sources kept"),
    "tool_ps_zip":     ("harmless", "PowerShell Compress-Archive"),
    "tool_robocopy_cp":("harmless", "robocopy /E copies the tree"),
    "tool_xcopy":      ("harmless", "xcopy copies the tree"),
    "tool_findstr":    ("harmless", "reads every file, writes nothing"),
    "tool_defender":   ("harmless", "antivirus scan of the profile"),
    "tool_attrib":     ("harmless", "attributes only"),
    "tool_acl":        ("harmless", "ownership and permissions"),
    "tool_taskkill":   ("harmless", "kills lock holders, stops services"),
    "tool_chrome":     ("harmless", "Chrome headless"),
    "tool_apps":       ("harmless", "notepad, mspaint, 7zFM, calc"),
    "tool_open_docs":  ("harmless", "opens documents in their handlers"),
    "tool_acrobat":    ("harmless", "Acrobat on the decoy PDFs"),
    "tool_media":      ("harmless", "images and media in their handlers"),
    "tool_session":    ("harmless", "three rounds of open, read, close"),
    "tool_ie_wmp":     ("harmless", "Internet Explorer and Media Player"),
}

ORDER = ["harmless", "ambiguous", "invisible", "destroys"]

HEADLINE = {
    "harmless": ("touched nothing that already existed",
                 "every one of these flagged is a false positive with no defence"),
    "ambiguous": ("same file trail as encryption, different reason",
                  "flagging these is not a defect: consent leaves no trace"),
    "invisible": ("contents destroyed through a path the sandbox does not record",
                  "not flagging these is the more serious result"),
    "destroys": ("the files that were there are gone",
                 "flagging these is the correct answer"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scores", required=True,
                         help="hardneg_scores.csv from train_model.py")
    parser.add_argument("--map", required=True,
                         help="hardneg_map.csv: task id to variant name")
    parser.add_argument("--verdicts", help="analyze_result output for the same runs")
    parser.add_argument("--flag-at", type=float, default=0.5,
                         help="Treat a variant as flagged when it was called "
                              "ransomware in at least this fraction of folds")
    args = parser.parse_args()

    variant = {}
    with open(os.path.expanduser(args.map), newline="") as f:
        for r in csv.DictReader(f):
            variant["H" + r["task_id"]] = r["variant"].replace(".exe", "")

    verdict = {}
    if args.verdicts:
        with open(args.verdicts, newline="") as f:
            for r in csv.DictReader(f):
                verdict["H" + str(r.get("task_id", "")).strip()] = r.get("verdict", "")

    rows = []
    with open(args.scores, newline="") as f:
        for r in csv.DictReader(f):
            sid = r["sample_id"]
            name = variant.get(sid, "?")
            cat, note = INTENT.get(name, ("unclassified", ""))
            rows.append({
                "id": sid, "name": name, "cat": cat, "note": note,
                "rate": float(r["flag_rate"]), "score": float(r["mean_score"]),
                "verdict": verdict.get(sid, ""),
            })

    unknown = [r for r in rows if r["cat"] == "unclassified"]
    if unknown:
        print(f"[note] {len(unknown)} variants are not in the table and are "
              f"listed at the end: {', '.join(r['name'] for r in unknown[:6])}")

    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["cat"]].append(r)

    print(f"\n{len(rows)} hard negatives, flagged when called ransomware in "
          f"{args.flag_at:.0%} or more of the folds\n")

    for cat in ORDER:
        group = sorted(by_cat.get(cat, []), key=lambda r: -r["rate"])
        if not group:
            continue
        flagged = [r for r in group if r["rate"] >= args.flag_at]
        title, gloss = HEADLINE[cat]
        print(f"=== {cat}: {title}")
        print(f"    {len(flagged)} of {len(group)} flagged -- {gloss}")
        print(f"    {'variant':<22}{'flagged':>9}{'score':>8}  {'verdict':<22}what it does")
        for r in group:
            mark = " " if r["rate"] >= args.flag_at else "."
            print(f"  {mark} {r['name']:<22}{r['rate']:>8.0%}{r['score']:>8.2f}  "
                  f"{r['verdict'][:20]:<22}{r['note']}")
        print()

    if unknown:
        print("=== unclassified")
        for r in sorted(unknown, key=lambda r: -r["rate"]):
            print(f"    {r['name']:<22}{r['rate']:>8.0%}{r['score']:>8.2f}")
        print()

    flagged_total = sum(1 for r in rows if r["rate"] >= args.flag_at)
    real_fp = [r for r in rows if r["cat"] == "harmless" and r["rate"] >= args.flag_at]
    missed = [r for r in rows if r["cat"] == "invisible" and r["rate"] < args.flag_at]

    print("summary")
    print(f"   flagged overall                        {flagged_total} of {len(rows)}")
    print(f"   of those, harmless                     {len(real_fp)}")
    print(f"   destroyed the contents but unrecorded  {len(missed)}")
    print()
    print("The overall count is not the false positive rate. Most of what was")
    print("flagged had in fact removed or replaced the user's files, and a")
    print("detector is meant to fire on that. The number that matters is the")
    print("harmless line -- and, in the other direction, the programs that")
    print("destroyed everything without leaving a single file event.")


if __name__ == "__main__":
    main()
