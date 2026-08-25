#!/usr/bin/env python3
"""
survey_behaviour.py - Two things at once: find out where CAPE records when a
process started, and survey what ground-clearing behaviour actually occurs
across the dataset.

Why both in one script
---------------------
Relational features need timestamps. `summary.executed_commands` lists what
ran but not when, so a delay between preparation and destruction cannot be
computed from it. Process creation is timestamped somewhere -- CAPE's own log
shows it -- but guessing which field holds it is how several earlier bugs
started, so part one prints the structure rather than assuming it.

Part two is the survey: how often each kind of preparation appears, split by
verdict. Counting these is cheap; deciding whether they are worth anything is
not, and that decision should follow the numbers.

Usage
-----
  # Part 1 only: show the structure of one report
  sudo python3 survey_behaviour.py --structure /opt/CAPEv2/storage/analyses/253

  # Part 2: survey everything, grouped by verdict
  sudo python3 survey_behaviour.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --results /tmp/results10.csv --out behaviour_survey.csv
"""

import os
import sys
import csv
import json
import argparse
from pathlib import Path
from collections import defaultdict

# Command-line fragments, grouped by what the attacker is trying to achieve
# rather than by which binary does it. Several binaries serve more than one
# purpose, so the phrase matters more than the executable name.
BEHAVIOUR_PATTERNS = {
    # Stop the victim undoing the damage
    "shadow_delete": ["vssadmin", "shadowcopy", "wbadmin", "delete shadows",
                       "delete catalog", "resize shadowstorage", "shadowstorage"],
    "recovery_disable": ["bcdedit", "recoveryenabled", "bootstatuspolicy",
                          "ignoreallfailures", "disable-computerrestore"],
    "backup_delete": ["wbadmin delete", "delete backup", "delete systemstatebackup"],

    # Get at files something else is holding open
    "service_stop": ["net stop", "sc stop", "sc.exe stop", "net1 stop",
                      "stop-service"],
    "process_kill": ["taskkill", "tskill", "process call terminate", "stop-process"],

    # Reach other machines
    "lateral_movement": ["net use", "net view", "psexec", "wmic /node",
                          "admin$", "c$", "ipc$", "invoke-command",
                          "enter-pssession"],

    # Survive a reboot
    "persistence": ["schtasks", "reg add", "currentversion\\\\run", "sc create",
                     "new-service", "startup"],

    # Remove traces
    "log_clear": ["wevtutil", "clear-eventlog", "cipher /w", "clearev"],

    # Reconnaissance before choosing what to hit
    "discovery": ["nltest", "net group", "net user", "whoami", "systeminfo",
                   "arp -a", "ipconfig", "net localgroup"],
}

# Executables whose appearance is itself the signal, used when the command
# line is unavailable but the process list is not.
PROCESS_MARKERS = {
    "vssadmin.exe": "shadow_delete",
    "wbadmin.exe": "backup_delete",
    "bcdedit.exe": "recovery_disable",
    "taskkill.exe": "process_kill",
    "wevtutil.exe": "log_clear",
    "net.exe": "service_stop_or_lateral",
    "net1.exe": "service_stop_or_lateral",
    "sc.exe": "service_stop",
    "wmic.exe": "wmic_any",
    "schtasks.exe": "persistence",
    "powershell.exe": "powershell",
    "cmd.exe": "shell",
    "nltest.exe": "discovery",
}


def show_structure(analysis_dir):
    """Print where timing information lives, without assuming a shape."""
    report = Path(analysis_dir) / "reports" / "report.json"
    if not report.exists():
        print(f"[!] no report at {report}")
        return
    with open(report, "r", errors="replace") as f:
        data = json.load(f)

    behavior = data.get("behavior", {}) or {}
    print(f"=== behavior keys ===\n   {list(behavior.keys())}\n")

    procs = behavior.get("processes", []) or []
    print(f"=== behavior.processes: {len(procs)} entries ===")
    if procs:
        first = procs[0]
        print(f"   keys on a process: {[k for k in first.keys() if k != 'calls']}")
        for p in procs[:6]:
            fields = {k: v for k, v in p.items()
                      if k != "calls" and not isinstance(v, (list, dict))}
            print(f"      {fields}")
    print()

    tree = behavior.get("processtree", []) or []
    print(f"=== behavior.processtree: {len(tree)} roots ===")
    if tree:
        node = tree[0]
        print(f"   keys on a node: {[k for k in node.keys() if k != 'children']}")
        fields = {k: v for k, v in node.items()
                  if k != "children" and not isinstance(v, (list, dict))}
        print(f"      {fields}")
    print()

    # Do individual calls carry timestamps? That would be the finest-grained
    # source of timing available.
    if procs and procs[0].get("calls"):
        call = procs[0]["calls"][0]
        print(f"=== a single API call ===")
        print(f"   keys: {list(call.keys())}")
        print(f"   {json.dumps({k: v for k, v in call.items() if k != 'arguments'})[:200]}")
    print()

    summary = behavior.get("summary", {}) or {}
    cmds = summary.get("executed_commands") or []
    print(f"=== summary.executed_commands: {len(cmds)} ===")
    for c in cmds[:8]:
        print(f"      {c[:110]}")


def classify_commands(commands):
    hits = defaultdict(int)
    for c in commands:
        low = c.lower()
        for name, patterns in BEHAVIOUR_PATTERNS.items():
            if any(pat in low for pat in patterns):
                hits[name] += 1
    return hits


def process_names(behavior):
    names = defaultdict(int)
    for p in behavior.get("processes", []) or []:
        n = (p.get("process_name") or p.get("name") or "").lower()
        if n:
            names[n] += 1
    return names


def survey_one(analysis_dir):
    report = Path(analysis_dir) / "reports" / "report.json"
    if not report.exists():
        return None
    try:
        with open(report, "r", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    behavior = data.get("behavior", {}) or {}
    summary = behavior.get("summary", {}) or {}
    commands = [c for c in (summary.get("executed_commands") or []) if isinstance(c, str)]

    row = {"task_id": Path(analysis_dir).name,
           "n_commands": len(commands),
           "n_processes": len(behavior.get("processes", []) or [])}

    hits = classify_commands(commands)
    for name in BEHAVIOUR_PATTERNS:
        row[name] = hits.get(name, 0)

    names = process_names(behavior)
    for exe, label in PROCESS_MARKERS.items():
        row[f"proc_{exe.replace('.exe','')}"] = names.get(exe, 0)

    row["n_services_created"] = len(summary.get("created_services") or [])
    row["n_services_started"] = len(summary.get("started_services") or [])
    row["n_registry_writes"] = len(summary.get("write_keys") or [])
    return row


def main():
    parser = argparse.ArgumentParser(
        description="Inspect process timing structure and survey preparation behaviour.")
    parser.add_argument("--structure", metavar="DIR",
                         help="Print the structure of one analysis and stop")
    parser.add_argument("--analyses-dir", default="/opt/CAPEv2/storage/analyses")
    parser.add_argument("--results", default=None,
                         help="analyze_result.py output, to group by verdict")
    parser.add_argument("--out", default="behaviour_survey.csv")
    args = parser.parse_args()

    if args.structure:
        show_structure(args.structure)
        return

    verdicts = {}
    if args.results and os.path.exists(args.results):
        with open(args.results, newline="") as f:
            for r in csv.DictReader(f):
                verdicts[str(r.get("task_id", "")).strip()] = r.get("verdict", "")

    base = Path(args.analyses_dir)
    dirs = sorted((p for p in base.iterdir() if p.is_dir() and p.name.isdigit()),
                   key=lambda p: int(p.name))

    rows = []
    for d in dirs:
        row = survey_one(d)
        if row:
            row["verdict"] = verdicts.get(row["task_id"], "")
            rows.append(row)

    if not rows:
        print("[!] nothing to survey")
        sys.exit(1)

    fields = list(rows[0].keys())
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    enc = [r for r in rows if r["verdict"] == "TRUE_ENCRYPTION"]
    non = [r for r in rows if r["verdict"] and r["verdict"] != "TRUE_ENCRYPTION"]

    print(f"surveyed {len(rows)} analyses "
          f"({len(enc)} encrypting, {len(non)} not, "
          f"{len(rows)-len(enc)-len(non)} unlabelled)\n")

    def share(group, key):
        if not group:
            return 0.0
        return sum(1 for r in group if r.get(key, 0) > 0) / len(group) * 100

    print("=== command-line behaviour: share of analyses showing it ===")
    print(f"{'behaviour':<22}{'encrypting':>12}{'not':>10}{'gap':>9}")
    print("-" * 53)
    for name in BEHAVIOUR_PATTERNS:
        e, n = share(enc, name), share(non, name)
        print(f"{name:<22}{e:>11.1f}%{n:>9.1f}%{e-n:>8.1f}")

    print("\n=== processes launched: share of analyses showing it ===")
    print(f"{'process':<22}{'encrypting':>12}{'not':>10}{'gap':>9}")
    print("-" * 53)
    marker_keys = sorted({f"proc_{e.replace('.exe','')}" for e in PROCESS_MARKERS})
    for key in marker_keys:
        e, n = share(enc, key), share(non, key)
        if e > 0 or n > 0:
            print(f"{key:<22}{e:>11.1f}%{n:>9.1f}%{e-n:>8.1f}")

    print(f"\n[saved] {args.out}")
    print("\nA large gap means the behaviour separates the two groups here. Note")
    print("that 'not encrypting' is mostly failed or inert runs, so a gap partly")
    print("reflects that those samples did little of anything -- the comparison")
    print("that settles it needs benign software run through the same sandbox.")


if __name__ == "__main__":
    main()
