#!/usr/bin/env python3
"""
find_retry_candidates.py - Separate analyses that failed because of the
sandbox from analyses that failed because of the sample.

Why this is needed
------------------
The host ran out of memory and the kernel killed the guest VM outright:

    Out of memory: Killed process 133805 (qemu-system-x86)
    Out of memory: Killed process 134229 (qemu-system-x86)
    Out of memory: Killed process 134365 (qemu-system-x86)

Three kills in half an hour. Every analysis running at those moments was
lost through no fault of the sample, and CAPE recorded them the same way it
records a sample that simply refused to run. Re-submitting them is free data;
re-submitting a sample that cannot execute is wasted sandbox time. The two
have to be told apart.

Two ways of telling them apart, both computed here
--------------------------------------------------
**Evidence-based (primary).** Two independent facts settle it:

  - Did an OOM kill fall inside this analysis's time window? The kernel
    records the moment it killed each qemu process, and CAPE records when
    each analysis ran, so the two can simply be intersected.
  - How does the guest-side analyzer log end? A run the analyzer finished
    ends with "Analysis completed". A run whose guest was killed mid-flight
    just stops, with no ending at all. A sample that could not be launched
    says so explicitly: "Unable to execute the initial process".

**Screenshot-absence (secondary, for comparison).** Simpler: if the analysis
produced no screenshots, assume the guest died. The weakness is that it
cannot distinguish causes. A sample that fails to launch may also leave few
or no screenshots, and re-submitting it changes nothing. Both signals are
reported side by side so the difference can be measured rather than assumed.

Usage
-----
  sudo python3 find_retry_candidates.py --analyses-dir /opt/CAPEv2/storage/analyses

  # Write the retry list, and optionally return those samples to pending
  sudo python3 find_retry_candidates.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --out retry.csv --manifest ../../../data/manifests/manifest_all.csv --reset-manifest
"""

import os
import re
import csv
import json
import sys
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# dmesg -T prints "[Thu Jul 30 20:56:06 2026] Out of memory: Killed process ..."
DMESG_KILL_RE = re.compile(
    r"\[(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\].*Killed process.*qemu")
DMESG_TIME_FORMAT = "%a %b %d %H:%M:%S %Y"

REPORT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# The analyzer says this when it could not launch the submitted file at all,
# which is a property of the sample and will recur on every attempt.
SAMPLE_LAUNCH_FAILURE = "unable to execute the initial process"

# The analyzer prints this only when it shuts itself down, having seen the
# sample exit. Ransomware usually keeps running until the analysis timeout,
# at which point CAPE stops the guest and the line is never written.
#
# Its absence therefore does NOT indicate a problem. Treating it as one
# classified successful runs -- 160,000 API calls, 40 screenshots -- as
# needing to be re-submitted.
ANALYZER_FINISHED = "analysis completed"

# API calls above which the sandbox is considered to have worked, whatever
# the log says.
#
# This was 500, borrowed from analyze_result's "did the sample do anything"
# gate. That is a different question. A sample can execute perfectly and make
# very few API calls: one opened a socket, initialised Windows CNG, and sat
# waiting for a connection that never came -- 263 calls, correctly monitored,
# and classified as an infrastructure failure needing re-submission.
#
# What matters here is whether the sandbox observed the guest, not whether
# the guest was busy. A few hundred recorded calls means the monitor was
# attached and working.
MIN_CALLS_FOR_USABLE_RUN = 100

# CAPE writes this to its own log when the guest stops answering. It is the
# direct statement that the guest died, as opposed to being inferred from
# call counts, and it distinguishes a sample that ran quietly from one whose
# guest was lost after recording a handful of calls.
AGENT_DEAD_RE = re.compile(r"Task #(\d+):.*Agent is dead")
CAPE_LOG = "/opt/CAPEv2/log/cuckoo.log"

# A guest killed at the same moment as a kernel OOM is attributed to it even
# if the recorded window is slightly off, since the clocks are seconds apart.
OOM_WINDOW_SLACK = timedelta(seconds=90)

MANIFEST_FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]


def read_agent_deaths(log_path):
    """
    Task ids CAPE reported as having lost their guest agent.

    Rotated logs are read too. CAPE's log rotates, so reading only the
    current file loses every older report -- an earlier run of this tool
    found a single agent death across the whole dataset because the rest had
    already been rotated away. Compressed archives are read as well.
    """
    ids = set()
    base = Path(log_path)
    candidates = [base]
    if base.parent.is_dir():
        candidates += sorted(base.parent.glob(base.name + ".*"))

    for path in candidates:
        if not path.exists():
            continue
        try:
            if path.suffix == ".gz":
                import gzip
                opener = lambda: gzip.open(path, "rt", errors="replace")
            else:
                opener = lambda: open(path, "r", errors="replace")
            with opener() as f:
                for line in f:
                    m = AGENT_DEAD_RE.search(line)
                    if m:
                        ids.add(m.group(1))
        except OSError:
            continue
    return ids


def read_oom_kills():
    """Times at which the kernel killed a qemu process."""
    try:
        out = subprocess.run(["dmesg", "-T"], capture_output=True, text=True,
                              timeout=30).stdout
    except Exception as e:
        print(f"[!] could not read dmesg ({e}); OOM correlation unavailable")
        return []

    kills = []
    for line in out.splitlines():
        m = DMESG_KILL_RE.search(line)
        if m:
            try:
                kills.append(datetime.strptime(m.group(1), DMESG_TIME_FORMAT))
            except ValueError:
                continue
    return sorted(kills)


def analysis_window(analysis_dir):
    """
    When the analysis ran. Taken from the report when there is one, and from
    file timestamps otherwise -- a guest that died early may leave no report.
    """
    report = analysis_dir / "reports" / "report.json"
    if report.exists():
        try:
            with open(report, "r", errors="replace") as f:
                info = json.load(f).get("info", {}) or {}
            started = info.get("started")
            ended = info.get("ended")
            if started and ended:
                return (datetime.strptime(started, REPORT_TIME_FORMAT),
                        datetime.strptime(ended, REPORT_TIME_FORMAT))
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    log = analysis_dir / "analysis.log"
    ref = log if log.exists() else analysis_dir
    try:
        stat = ref.stat()
        end = datetime.fromtimestamp(stat.st_mtime)
        start = datetime.fromtimestamp(stat.st_ctime)
        return (min(start, end), end)
    except OSError:
        return (None, None)


def analysis_reports_agent_death(analysis_dir):
    """
    CAPE also writes a per-analysis cuckoo.log next to the results. That copy
    does not rotate, so it survives when the central log has moved on.
    """
    log = Path(analysis_dir) / "cuckoo.log"
    if not log.exists():
        return False
    try:
        with open(log, "r", errors="replace") as f:
            return "agent is dead" in f.read().lower()
    except OSError:
        return False


def read_analyzer_outcome(analysis_dir):
    """
    Classify how the guest-side analyzer ended.

    Returns one of: "sample_launch_failed", "finished", "truncated", "no_log".
    """
    log = analysis_dir / "analysis.log"
    if not log.exists():
        return "no_log"
    try:
        with open(log, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        return "no_log"

    lowered = text.lower()
    if SAMPLE_LAUNCH_FAILURE in lowered:
        return "sample_launch_failed"
    if ANALYZER_FINISHED in lowered:
        return "finished"
    return "truncated"


def count_shots(analysis_dir):
    shots = analysis_dir / "shots"
    if not shots.is_dir():
        return 0
    return sum(1 for p in shots.iterdir()
               if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".bmp"))


def total_calls(analysis_dir):
    report = analysis_dir / "reports" / "report.json"
    if not report.exists():
        return None
    try:
        with open(report, "r", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    return sum(len(p.get("calls", []) or [])
               for p in data.get("behavior", {}).get("processes", []) or [])


def classify(outcome, oom_hit, calls, agent_died):
    """
    Decide whether re-submitting is worth the sandbox time.

    The first question is whether the run produced behavioural data, not how
    its log ended. A ransomware sample that works keeps running until the
    timeout, so its log has no closing line -- reading that as damage marked
    every successful analysis for re-submission.

    Only once it is established that nothing usable came out does the cause
    matter, and then it decides whether trying again could change anything.
    """
    # The guest being declared dead outranks the call count: a run can record
    # a few hundred calls and then lose its guest, which is still a lost run.
    if agent_died:
        return "RETRY", "CAPE reported the guest agent dead"

    if calls is not None and calls >= MIN_CALLS_FOR_USABLE_RUN:
        return "NO_RETRY", "sandbox observed the guest; the sample was simply quiet"

    if oom_hit:
        return "RETRY", "guest killed by the host running out of memory"
    if outcome == "sample_launch_failed":
        return "NO_RETRY", "sample could not be launched (wrong architecture, corrupt PE)"
    if outcome == "no_log":
        return "RETRY", "analyzer never started; the guest was not reachable"
    if outcome == "truncated":
        return "RETRY", "no data and the analyzer log stops mid-run"
    return "NO_RETRY", "analyzer finished but recorded nothing"


FIELDNAMES = ["task_id", "decision", "reason", "analyzer_outcome", "oom_hit",
              "agent_died", "shots", "total_calls", "started", "ended",
              "screenshot_heuristic", "signals_agree"]


def main():
    parser = argparse.ArgumentParser(
        description="Identify analyses worth re-submitting after sandbox failures.")
    parser.add_argument("--analyses-dir", default="/opt/CAPEv2/storage/analyses")
    parser.add_argument("--out", default=None, help="CSV output path")
    parser.add_argument("--manifest", default=None,
                         help="Manifest CSV; with --reset-manifest, retry candidates "
                              "are returned to pending")
    parser.add_argument("--reset-manifest", action="store_true",
                         help="Set retry candidates back to pending in the manifest")
    parser.add_argument("--cape-log", default=CAPE_LOG,
                         help=f"CAPE's own log, read for agent-death reports "
                              f"(default: {CAPE_LOG})")
    parser.add_argument("--only-failed", action="store_true",
                         help="Only consider analyses with no calls recorded, which is "
                              "where sandbox failures concentrate")
    args = parser.parse_args()

    base = Path(args.analyses_dir)
    if not base.is_dir():
        print(f"[!] not a directory: {args.analyses_dir}")
        sys.exit(1)

    kills = read_oom_kills()
    print(f"OOM kills of qemu found in the kernel log: {len(kills)}")
    for k in kills:
        print(f"   {k}")

    agent_deaths = read_agent_deaths(args.cape_log)
    print(f"Tasks whose guest agent CAPE declared dead: {len(agent_deaths)}")
    print()

    dirs = sorted((p for p in base.iterdir() if p.is_dir() and p.name.isdigit()),
                   key=lambda p: int(p.name))

    rows = []
    for d in dirs:
        calls = total_calls(d)
        if args.only_failed and calls not in (0, None):
            continue

        started, ended = analysis_window(d)
        oom_hit = False
        if started and ended:
            lo, hi = started - OOM_WINDOW_SLACK, ended + OOM_WINDOW_SLACK
            oom_hit = any(lo <= k <= hi for k in kills)

        outcome = read_analyzer_outcome(d)
        agent_died = d.name in agent_deaths or analysis_reports_agent_death(d)
        decision, reason = classify(outcome, oom_hit, calls, agent_died)
        shots = count_shots(d)

        # The simpler rule, kept alongside so the two can be compared.
        screenshot_rule = "RETRY" if shots == 0 else "NO_RETRY"

        rows.append({
            "task_id": d.name,
            "decision": decision,
            "reason": reason,
            "analyzer_outcome": outcome,
            "oom_hit": int(oom_hit),
            "agent_died": int(agent_died),
            "shots": shots,
            "total_calls": "" if calls is None else calls,
            "started": started.strftime(REPORT_TIME_FORMAT) if started else "",
            "ended": ended.strftime(REPORT_TIME_FORMAT) if ended else "",
            "screenshot_heuristic": screenshot_rule,
            "signals_agree": int(decision == screenshot_rule),
        })

    retry = [r for r in rows if r["decision"] == "RETRY"]

    header = (f"{'task':<7} {'decision':<10} {'analyzer':<22} {'oom':>4} {'dead':>5} "
              f"{'shots':>6} {'calls':>8} {'shot-rule':<10} {'agree'}")
    print(header)
    print("-" * len(header))
    for r in rows:
        mark = "" if r["signals_agree"] else "  <-- differ"
        print(f"{r['task_id']:<7} {r['decision']:<10} {r['analyzer_outcome']:<22} "
              f"{r['oom_hit']:>4} {r['agent_died']:>5} {r['shots']:>6} "
              f"{str(r['total_calls']):>8} "
              f"{r['screenshot_heuristic']:<10} {r['signals_agree']}{mark}")

    print(f"\n=== decisions ===")
    by_reason = defaultdict(int)
    for r in rows:
        by_reason[(r["decision"], r["reason"])] += 1
    for (dec, reason), n in sorted(by_reason.items(), key=lambda x: (-x[1])):
        print(f"   {dec:<9} {n:>4}   {reason}")

    print(f"\n=== the two signals compared ===")
    agree = sum(r["signals_agree"] for r in rows)
    print(f"   agree      : {agree}/{len(rows)}")
    disagree = [r for r in rows if not r["signals_agree"]]
    if disagree:
        print(f"   disagree   : {len(disagree)}")
        ev_only = [r for r in disagree if r["decision"] == "RETRY"]
        sh_only = [r for r in disagree if r["screenshot_heuristic"] == "RETRY"]
        if ev_only:
            print(f"      evidence says retry, screenshots say no : "
                  f"{[r['task_id'] for r in ev_only][:15]}")
            print(f"         (the guest died but had already produced screenshots)")
        if sh_only:
            print(f"      screenshots say retry, evidence says no : "
                  f"{[r['task_id'] for r in sh_only][:15]}")
            print(f"         (no screenshots, but the sample itself was the problem --")
            print(f"          re-submitting these would waste sandbox time)")

    print(f"\n=== worth re-submitting: {len(retry)} ===")
    if retry:
        print(f"   {[r['task_id'] for r in retry]}")

    if args.out:
        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n[saved] {args.out}")

    if args.reset_manifest and args.manifest and retry:
        if not os.path.exists(args.manifest):
            print(f"[!] manifest not found: {args.manifest}")
            return
        task_ids = {r["task_id"] for r in retry}
        with open(args.manifest, newline="") as f:
            manifest_rows = list(csv.DictReader(f))
        n = 0
        for row in manifest_rows:
            if (row.get("cape_task_id") or "").strip() in task_ids:
                row["status"] = "pending"
                row["cape_task_id"] = ""
                row["result"] = ""
                row["notes"] = (row.get("notes", "") + ";retry_after_host_oom").strip(";")
                n += 1
        with open(args.manifest, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDNAMES)
            writer.writeheader()
            for row in manifest_rows:
                writer.writerow({k: row.get(k, "") for k in MANIFEST_FIELDNAMES})
        print(f"[manifest] {n} sample(s) returned to pending")
    elif args.reset_manifest and not args.manifest:
        print("\n[!] --reset-manifest needs --manifest")


if __name__ == "__main__":
    main()
