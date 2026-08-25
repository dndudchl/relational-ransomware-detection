#!/usr/bin/env python3
"""
run_pipeline.py - Run the post-analysis pipeline end to end.

The individual stages stay as separate scripts so each can be re-run on its
own (feature definitions change often; verdicts rarely do). This
orchestrator chains them so that in normal use a single command carries an
analysis from "CAPE just finished" to "row in the feature table, original
report archived".

Stages
------
  1. analyze_result.py   -> verdict per analysis (execution + encryption),
                            manifest updated automatically
  2. extract_features.py -> dynamic + static + interaction features for the
                            analyses that reached TRUE_ENCRYPTION
  3. cleanup             -> archive the raw reports, but ONLY for analyses
                            whose features were successfully extracted

Safety
------
Cleanup is destructive (it deletes analysis directories after archiving), so
it is opt-in via --cleanup and it only ever touches analyses that appear in
the feature table produced by stage 2. If stage 2 failed or produced nothing,
nothing is deleted. --dry-run shows the plan without changing anything.

Usage
-----
  # Full run, no deletion
  python3 run_pipeline.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --features-out ../../data/features.csv \\
      --manifest ../../data/manifests/manifest_all.csv

  # Same, then archive+delete processed analyses
  python3 run_pipeline.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --features-out ../../data/features.csv \\
      --manifest ../../data/manifests/manifest_all.csv \\
      --cleanup --archive-dir ~/ransomware_reports

  # See what would happen, change nothing
  python3 run_pipeline.py --analyses-dir /opt/CAPEv2/storage/analyses --dry-run
"""

import os
import sys
import csv
import gzip
import shutil
import argparse
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ANALYZE_SCRIPT = SCRIPT_DIR / "analyze_result.py"
EXTRACT_SCRIPT = SCRIPT_DIR / "features" / "extract_features.py"


def run_stage(cmd, description):
    """Run a stage as a subprocess, streaming its output. Returns success bool."""
    print(f"\n{'=' * 70}")
    print(f"  {description}")
    print(f"{'=' * 70}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\n[!] stage failed: {description}")
        return False
    return True


def read_verdicts(results_csv, keep_verdict):
    """Return the set of task ids that reached the desired verdict."""
    if not os.path.exists(results_csv):
        return set()
    passed = set()
    with open(results_csv, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("verdict") == keep_verdict:
                passed.add(str(row.get("task_id", "")).strip())
    return passed


def read_extracted_ids(features_csv):
    """Return the set of sample ids present in the feature table."""
    if not features_csv or not os.path.exists(features_csv):
        return set()
    ids = set()
    with open(features_csv, newline="") as f:
        for row in csv.DictReader(f):
            sid = str(row.get("sample_id", "")).strip()
            if sid:
                ids.add(sid)
    return ids


def remove_analysis_dir(task_dir, analyses_dir):
    """
    Delete one analysis directory, falling back to CAPE's own user.

    CAPE creates parts of each analysis (the CAPE/ subdirectory in
    particular) as the user it runs as, which the account running this
    pipeline usually cannot remove. A plain rmtree then raises PermissionError
    partway through -- and, before this was handled, aborted the entire
    cleanup run, leaving the disk full.

    Falling back to `sudo -u cape rm -rf` works because that user owns the
    files. The path is checked to be inside the analyses directory first: a
    recursive delete run as another user is not something to hand an
    unvalidated path.
    """
    task_dir = Path(task_dir).resolve()
    base = Path(analyses_dir).resolve()

    try:
        shutil.rmtree(task_dir)
        return True
    except PermissionError:
        pass
    except OSError as e:
        print(f"   [!] could not delete {task_dir.name}: {e}")
        return False

    # Refuse anything that is not a numbered analysis directly under the base.
    if task_dir.parent != base or not task_dir.name.isdigit():
        print(f"   [!] refusing to delete {task_dir} as another user: "
              f"not an analysis directory under {base}")
        return False

    try:
        result = subprocess.run(
            ["sudo", "-n", "-u", "cape", "rm", "-rf", str(task_dir)],
            capture_output=True, text=True, timeout=120)
    except Exception as e:
        print(f"   [!] could not delete {task_dir.name}: {e}")
        return False

    if result.returncode == 0 and not task_dir.exists():
        return True

    err = (result.stderr or "").strip()
    print(f"   [!] could not delete {task_dir.name}: {err[:120]}")
    return False


def cleanup_analyses(analyses_dir, archive_dir, extracted_ids, results_csv,
                      keep_verdict, dry_run):
    """
    Archive and remove analyses.

    Three classes are handled differently, mirroring the conservative
    behaviour of the original triage tool:

      - Features extracted (TRUE_ENCRYPTION): gzip the report to the archive
        directory, then delete the analysis directory. The archive allows
        re-extracting features later if feature definitions change, without
        re-running the sandbox.

      - Ran but did not qualify (WEAK_VICTIM_ACTIVITY, NO_VICTIM_ACTIVITY):
        ALSO archived before deletion. These are not useless -- weak cases
        may deserve manual review, and non-victim cases document sandbox
        evasion / self-installation behaviour, which is itself a finding.
        Deleting them without a backup would be irreversible data loss.

      - Never really executed (FAILED): archived as well. This changed once
        static features were harvested from non-qualifying analyses: a FAILED
        analysis still carries a readable import table, so if the static
        feature definitions change later, its report must still exist to
        re-extract from. Compressed reports are cheap (roughly 100MB -> 10-20MB),
        so the safe default is to keep everything.
    """
    analyses_path = Path(analyses_dir)
    archive_path = Path(archive_dir).expanduser()

    if not dry_run:
        archive_path.mkdir(parents=True, exist_ok=True)

    # Classify every analysis the verdict stage saw, so we never touch
    # directories that are still being analysed.
    verdict_by_id = {}
    if os.path.exists(results_csv):
        with open(results_csv, newline="") as f:
            for row in csv.DictReader(f):
                verdict_by_id[str(row.get("task_id", "")).strip()] = row.get("verdict", "")

    archived = deleted = skipped = failed = 0

    for task_dir in sorted(analyses_path.iterdir(), key=lambda d: d.name):
        if not task_dir.is_dir():
            continue
        tid = task_dir.name

        if tid not in verdict_by_id:
            # Not part of this run (e.g. still analysing). Leave alone.
            skipped += 1
            continue

        verdict = verdict_by_id[tid]
        report = task_dir / "reports" / "report.json"

        if tid in extracted_ids:
            reason = "features extracted"
            should_archive = True
        elif verdict == keep_verdict:
            # Passed the verdict but produced no feature row: extraction must
            # have failed. Keep the directory intact for investigation.
            print(f"   [keep] task {tid} passed verdict but has no feature row "
                  f"-- keeping for investigation")
            skipped += 1
            continue
        elif verdict == "FAILED":
            reason = "did not execute (static features may still apply)"
            should_archive = True
        else:
            # WEAK_VICTIM_ACTIVITY / NO_VICTIM_ACTIVITY: worth preserving.
            reason = f"{verdict} (kept for review)"
            should_archive = True

        if should_archive and report.exists():
            target = archive_path / f"task_{tid}_report.json.gz"
            if dry_run:
                print(f"   [dry-run] would archive task {tid} ({reason}) -> {target.name}")
                archived += 1
            else:
                # Archive first, and do not delete unless it succeeded. The
                # archive is the only copy that survives; writing it can fail
                # for the same reason cleanup was needed in the first place --
                # a full disk -- and deleting anyway would destroy the report
                # to reclaim space that the archive was supposed to save.
                tmp = target.with_suffix(".gz.part")
                try:
                    with open(report, "rb") as src, gzip.open(tmp, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    tmp.replace(target)
                    archived += 1
                except OSError as e:
                    print(f"   [!] could not archive task {tid}: {e}")
                    print(f"       keeping the analysis directory")
                    tmp.unlink(missing_ok=True)
                    failed += 1
                    continue

        if dry_run:
            print(f"   [dry-run] would delete analysis dir {tid} ({reason})")
            deleted += 1
        elif remove_analysis_dir(task_dir, analyses_dir):
            deleted += 1
        else:
            failed += 1

    print(f"\n[cleanup] archived={archived} deleted={deleted} kept={skipped}"
          + (f" failed={failed}" if failed else ""))
    if failed:
        print(f"[cleanup] {failed} directories were kept: either the archive could")
        print(f"          not be written, or the directory could not be removed.")
        print(f"          CAPE writes some files as its own user, so deleting")
        print(f"          them needs either NOPASSWD sudo for that user, or")
        print(f"          a manual pass:")
        print(f"             sudo rm -rf {analyses_dir}/<id>")
    if dry_run:
        print("[cleanup] dry run -- nothing was actually changed")


def main():
    parser = argparse.ArgumentParser(
        description="Run verdict -> feature extraction -> cleanup as one command.")
    parser.add_argument("--analyses-dir", default="/opt/CAPEv2/storage/analyses",
                         help="CAPE storage/analyses directory")
    parser.add_argument("--features-out", default=None,
                         help="Feature table CSV to append to")
    parser.add_argument("--manifest", default=None,
                         help="Manifest CSV (auto-updated with verdicts, "
                              "and used to tag features with family)")
    parser.add_argument("--results-out", default="analysis_results.csv",
                         help="Where to write the verdict CSV (default: analysis_results.csv)")
    parser.add_argument("--keep-verdict", default="TRUE_ENCRYPTION",
                         help="Verdict that gets FULL (dynamic + static) features")
    parser.add_argument("--static-for-all", action="store_true",
                         help="Also emit static-only rows for analyses that did not reach "
                              "--keep-verdict, instead of discarding them")
    parser.add_argument("--label", default="ransomware", help="Label for extracted rows")
    parser.add_argument("--window", type=float, default=1.0,
                         help="Correlation window in seconds (default: 1.0)")
    parser.add_argument("--cleanup", action="store_true",
                         help="After extraction, archive and remove processed analyses")
    parser.add_argument("--archive-dir", default="~/ransomware_reports",
                         help="Where gzipped reports are archived")
    parser.add_argument("--dry-run", action="store_true",
                         help="Show what would happen without changing anything")
    args = parser.parse_args()

    if not Path(args.analyses_dir).is_dir():
        print(f"[!] analyses directory not found: {args.analyses_dir}")
        sys.exit(1)

    # ---- Stage 1: verdicts ----
    # Stage 1 only reads the analyses and writes a verdict CSV, so it is safe
    # to run even during a dry run -- and running it is what makes the dry run
    # informative, since the plan for stages 2 and 3 depends on the verdicts.
    # The manifest is left untouched in dry-run mode.
    results_target = args.results_out
    if args.dry_run:
        results_target = args.results_out + ".dryrun"

    cmd = [sys.executable, str(ANALYZE_SCRIPT),
           "--batch", args.analyses_dir,
           "--out", results_target]
    if args.manifest and not args.dry_run:
        cmd += ["--manifest", args.manifest]

    label = "Stage 1/3: execution + encryption verdict"
    if args.dry_run:
        label += "  (dry run: manifest not modified)"
    if not run_stage(cmd, label):
        sys.exit(1)
    args.results_out = results_target

    passed = read_verdicts(args.results_out, args.keep_verdict)
    print(f"\n[pipeline] {len(passed)} analyses reached {args.keep_verdict}")

    if not passed and not args.static_for_all:
        print("[pipeline] nothing to extract; stopping here.")
        print("           (pass --static-for-all to still harvest static features "
              "from analyses that did not qualify)")
        if args.dry_run and os.path.exists(args.results_out):
            os.remove(args.results_out)
        return

    # ---- Stage 2: feature extraction ----
    if not args.features_out:
        print("\n[pipeline] no --features-out given; skipping extraction.")
        print("           (verdicts are recorded; re-run with --features-out to extract)")
        return

    cmd = [sys.executable, str(EXTRACT_SCRIPT),
           "--batch", args.analyses_dir,
           "--results", args.results_out,
           "--keep-verdict", args.keep_verdict,
           "--features-out", args.features_out,
           "--label", args.label,
           "--window", str(args.window)]
    if args.static_for_all:
        cmd.append("--static-for-all")
    if args.manifest:
        cmd += ["--manifest", args.manifest]

    if args.dry_run:
        print(f"\n[dry-run] stage 2 would extract features from {len(passed)} "
              f"analyses into {args.features_out}")
        print(f"[dry-run] task ids: {sorted(passed)}")
        if args.cleanup:
            print(f"[dry-run] stage 3 would then archive those reports to "
                  f"{args.archive_dir} and delete their analysis directories,")
            print(f"[dry-run] and delete failed analyses outright (no archive).")
        else:
            print(f"[dry-run] stage 3 (cleanup) not requested; raw analyses would be kept.")
        os.remove(args.results_out)  # remove the temporary dry-run verdict file
        return
    if not run_stage(cmd, "Stage 2/3: dynamic + static feature extraction"):
        print("[!] extraction failed; skipping cleanup to protect raw data.")
        sys.exit(1)

    # ---- Stage 3: cleanup (opt-in, only for successfully extracted) ----
    if not args.cleanup:
        print("\n[pipeline] cleanup not requested (--cleanup to enable). Raw analyses kept.")
        return

    extracted_ids = read_extracted_ids(args.features_out)
    ready = passed & extracted_ids
    print(f"\n{'=' * 70}")
    print(f"  Stage 3/3: cleanup")
    print(f"{'=' * 70}")
    print(f"[cleanup] {len(ready)} of {len(passed)} passing analyses have feature rows")

    if len(ready) < len(passed):
        missing = passed - extracted_ids
        print(f"[cleanup] {len(missing)} passing analyses have NO feature row and "
              f"will be kept: {sorted(missing)[:10]}")

    cleanup_analyses(args.analyses_dir, args.archive_dir, ready,
                      args.results_out, args.keep_verdict, args.dry_run)


if __name__ == "__main__":
    main()
