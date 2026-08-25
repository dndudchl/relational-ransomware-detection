#!/usr/bin/env python3
"""
check_kill_effect.py - Test whether samples that kill processes fail to
encrypt, or only fail to be *seen* encrypting.

The observation
---------------
Among runs of comparable activity, samples that launched taskkill reached
encryption 29% of the time against 80% for those that did not. That is a
large gap in the wrong direction: killing processes is preparation, so it
should accompany encryption rather than replace it.

Two explanations, with different consequences
---------------------------------------------
**Measurement.** The sandbox agent runs as python.exe. Ransomware freeing
file locks kills processes in bulk and the agent is not spared -- this was
observed directly in one analysis, where the agent stopped responding one
second after bcdedit ran. If the agent dies mid-run, everything after that
point is unrecorded, and the sample looks like it prepared and stopped. The
gap would then be an artefact of our own instrument.

**Behaviour.** The samples really did spend their time on preparation and
never got to encrypting.

The two are distinguishable. A run cut short by a dying agent ends early and
leaves CAPE reporting the agent dead; a run that simply did not encrypt uses
its full analysis window and ends normally.

A third possibility worth checking
----------------------------------
Seven of the fourteen process-killing runs are the same family. If that
family does not detonate here for unrelated reasons, the gap is neither
measurement nor behaviour but confounding, and says nothing about killing
processes at all.

Usage
-----
  sudo python3 check_kill_effect.py --features ../../../data/features.csv \\
      --analyses-dir /opt/CAPEv2/storage/analyses
"""

import os
import re
import csv
import json
import argparse
from pathlib import Path
from collections import defaultdict

AGENT_DEAD_RE = re.compile(r"Agent is dead", re.IGNORECASE)


def analysis_facts(analyses_dir, task_id):
    """Duration, whether the window was used up, and whether the agent died."""
    d = Path(analyses_dir) / str(task_id)
    facts = {"duration": None, "hit_timeout": None, "agent_died": False,
             "n_shots": 0, "family": ""}

    report = d / "reports" / "report.json"
    if report.exists():
        try:
            with open(report, "r", errors="replace") as f:
                data = json.load(f)
            info = data.get("info", {}) or {}
            facts["duration"] = info.get("duration")
            facts["hit_timeout"] = info.get("timeout")
            dets = data.get("detections") or []
            facts["family"] = (dets[0].get("family") if dets else "") or ""
        except (json.JSONDecodeError, OSError):
            pass

    log = d / "cuckoo.log"
    if log.exists():
        try:
            with open(log, "r", errors="replace") as f:
                facts["agent_died"] = bool(AGENT_DEAD_RE.search(f.read()))
        except OSError:
            pass

    shots = d / "shots"
    if shots.is_dir():
        facts["n_shots"] = sum(1 for p in shots.iterdir()
                               if p.suffix.lower() in (".png", ".jpg", ".jpeg"))
    return facts


def main():
    parser = argparse.ArgumentParser(
        description="Test whether process-killing runs were cut short.")
    parser.add_argument("--features", default="../../../data/features.csv")
    parser.add_argument("--analyses-dir", default="/opt/CAPEv2/storage/analyses")
    parser.add_argument("--feature", default="n_process_kill",
                         help="Which preparation feature to test (default: n_process_kill)")
    args = parser.parse_args()

    rows = []
    with open(args.features, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("coverage") != "full":
                continue
            try:
                v = int(r.get(args.feature) or 0)
            except ValueError:
                v = 0
            rows.append((r["sample_id"], v > 0, r.get("verdict", "")))

    killers = [t for t, k, _v in rows if k]
    others = [t for t, k, _v in rows if not k]
    print(f"runs with {args.feature} > 0 : {len(killers)}")
    print(f"runs without               : {len(others)}\n")
    if not killers:
        print("[!] nothing to test")
        return

    facts = {t: analysis_facts(args.analyses_dir, t) for t in killers}

    print(f"=== every run with {args.feature} > 0 ===")
    print(f"{'task':<7}{'verdict':<22}{'duration':>9}{'timeout':>9}"
          f"{'agent died':>12}{'shots':>7}  family")
    print("-" * 78)
    verdict_of = {t: v for t, _k, v in rows}
    for t in sorted(killers, key=lambda x: int(x) if x.isdigit() else 0):
        f = facts[t]
        print(f"{t:<7}{verdict_of[t][:20]:<22}{str(f['duration']):>9}"
              f"{str(f['hit_timeout']):>9}{str(f['agent_died']):>12}"
              f"{f['n_shots']:>7}  {f['family']}")

    # ---- was the analysis cut short? ----
    died = [t for t in killers if facts[t]["agent_died"]]
    full_window = [t for t in killers if facts[t]["hit_timeout"] is True]
    print(f"\n=== was the analysis cut short? ===")
    print(f"   CAPE reported the agent dead : {len(died)}/{len(killers)}")
    print(f"   used the full analysis window: {len(full_window)}/{len(killers)}")
    if died:
        print(f"      {sorted(died, key=lambda x: int(x))}")
    if len(died) == 0 and len(full_window) >= len(killers) * 0.7:
        print("   -> these runs were not cut short. The instrument is not the")
        print("      explanation; they had the time and did not encrypt.")
    elif len(died) >= len(killers) * 0.5:
        print("   -> most were cut short. The gap is largely our own measurement")
        print("      failing, not the samples failing.")
    else:
        print("   -> mixed; neither explanation accounts for all of them.")

    # ---- is one family responsible? ----
    fam = defaultdict(list)
    for t in killers:
        fam[facts[t]["family"] or "(unattributed)"].append(t)
    print(f"\n=== which families kill processes ===")
    for name, ts in sorted(fam.items(), key=lambda kv: -len(kv[1])):
        enc = sum(1 for t in ts if verdict_of[t] == "TRUE_ENCRYPTION")
        print(f"   {name:<20} {len(ts):>3} runs, {enc} encrypted")

    biggest = max(fam.items(), key=lambda kv: len(kv[1]))
    if len(biggest[1]) >= len(killers) * 0.4:
        print(f"\n   {biggest[0]} accounts for {len(biggest[1])} of {len(killers)}.")
        print(f"   Whether that family encrypts here at all needs checking before")
        print(f"   the gap is read as being about killing processes.")

        # how does that family fare overall, killing or not?
        all_fam = []
        for t, _k, v in rows:
            ff = analysis_facts(args.analyses_dir, t)
            if ff["family"] == biggest[0]:
                all_fam.append((t, v))
        if all_fam:
            enc = sum(1 for _t, v in all_fam if v == "TRUE_ENCRYPTION")
            print(f"   Across all {len(all_fam)} {biggest[0]} runs analysed, "
                  f"{enc} encrypted ({enc/len(all_fam)*100:.0f}%).")


if __name__ == "__main__":
    main()
