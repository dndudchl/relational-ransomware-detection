#!/usr/bin/env python3
"""
healthcheck.py - Detect and recover from CAPE's stuck-machine failure mode.

The failure
-----------
CAPE can reach a state where it believes no analysis machine is available,
even though the VM is fine. Every queued task is then failed immediately:

    Task #171: Failing unserviceable task because no matching machine could
    be found. Requested tags: 'x86'. Available machine tags: {}

Note the empty tag dict: the problem is not a tag mismatch, it is that CAPE
has no usable machine registered at all. Once in this state it does not
recover on its own, and because tasks fail in milliseconds rather than
minutes, a queue that should have lasted overnight is consumed in seconds.
This happened once already and cost 42 samples (tasks 159-200).

Restarting the CAPE service clears it -- the machine is re-registered
("Loaded 1 machine") and analysis resumes.

Why this needs to be automated
------------------------------
For unattended operation this is the most damaging failure available. Disk
exhaustion is gradual and visible; a stuck machine silently burns the entire
queue. Detecting it within a few minutes is the difference between losing
one sample and losing a whole batch.

What this script does
---------------------
  1. Reads recent CAPE log entries (default: last 20 minutes) and looks for
     the unserviceable-task signature.
  2. Extracts the affected task IDs directly from those log lines, so
     recovery is precise rather than a guessed range.
  3. With --fix: restarts CAPE, waits for the machine to be re-registered,
     and sets the affected tasks back to pending in the manifest so they get
     resubmitted by the next batch.

Without --fix it only reports, which is the safe default.

Requirements
------------
Restarting the service needs sudo. For unattended use, allow it without a
password prompt, e.g. in /etc/sudoers.d/cape-healthcheck:

    young ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart cape
    young ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active cape

Usage
-----
  # Report only
  python3 healthcheck.py --manifest ../../../data/manifests/manifest_all.csv

  # Detect and recover
  python3 healthcheck.py --manifest ../../../data/manifests/manifest_all.csv --fix

  # From cron, every 10 minutes
  */10 * * * * cd /path/to/src && /path/to/.venv/bin/python3 healthcheck.py \\
      --manifest /path/to/data/manifest.csv --fix >> ~/healthcheck.log 2>&1
"""

import os
import re
import csv
import sys
import time
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

DEFAULT_LOG = "/opt/CAPEv2/log/cuckoo.log"
DEFAULT_STATE = os.path.expanduser("~/.cape_healthcheck_state.json")

LOG_TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# The unserviceable-task signature, with the task id captured.
UNSERVICEABLE_RE = re.compile(
    r"Task #(\d+): Failing unserviceable task because no matching machine")
# Confirmation that a restart worked.
MACHINE_LOADED_RE = re.compile(r"Loaded (\d+) machine")

# Minimum gap between restarts, so a persistent fault does not turn into a
# restart loop that never lets CAPE finish starting up.
RESTART_COOLDOWN_SECONDS = 900

MANIFEST_FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]


def parse_log_timestamp(line):
    """CAPE log lines start with 'YYYY-MM-DD HH:MM:SS,mmm'."""
    if len(line) < 19:
        return None
    try:
        return datetime.strptime(line[:19], LOG_TS_FORMAT)
    except ValueError:
        return None


def read_recent_lines(log_path, window_minutes, max_bytes=8_000_000):
    """
    Read the tail of the log and keep entries newer than the window.

    Only the tail is read because this log grows without bound and the
    interesting events are always the most recent ones.
    """
    path = Path(log_path)
    if not path.exists():
        return None, f"log not found: {log_path}"

    try:
        size = path.stat().st_size
        with open(path, "r", errors="replace") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # discard the partial line
            lines = f.readlines()
    except OSError as e:
        return None, f"cannot read log: {e}"

    cutoff = datetime.now() - timedelta(minutes=window_minutes)
    recent = []
    for line in lines:
        ts = parse_log_timestamp(line)
        if ts is None:
            # Continuation lines inherit the position of the previous entry.
            if recent:
                recent.append(line)
            continue
        if ts >= cutoff:
            recent.append(line)
    return recent, None


def detect_stuck_machine(recent_lines):
    """Return the set of task ids failed by the unserviceable-machine fault."""
    task_ids = set()
    for line in recent_lines:
        m = UNSERVICEABLE_RE.search(line)
        if m:
            task_ids.add(m.group(1))
    return task_ids


def service_is_active(service):
    try:
        result = subprocess.run(["systemctl", "is-active", service],
                                 capture_output=True, text=True, timeout=15)
        return result.stdout.strip() == "active"
    except Exception:
        return None  # unknown


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    try:
        with open(path, "w") as f:
            json.dump(state, f)
    except OSError:
        pass


def restart_cape(service, log_path, wait_seconds):
    """Restart CAPE and confirm a machine was re-registered."""
    print(f"   restarting {service} ...")
    try:
        result = subprocess.run(["sudo", "systemctl", "restart", service],
                                 capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("   [!] restart timed out")
        return False
    except Exception as e:
        print(f"   [!] restart failed: {e}")
        return False

    if result.returncode != 0:
        err = (result.stderr or "").strip()
        print(f"   [!] restart returned {result.returncode}: {err[:200]}")
        if "password" in err.lower() or "sudo" in err.lower():
            print("   [!] sudo appears to require a password; see the NOPASSWD")
            print("       note in this script's docstring for unattended use.")
        return False

    # Confirm recovery by looking for the machine-registration line.
    print(f"   waiting up to {wait_seconds}s for the machine to register ...")
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        time.sleep(5)
        recent, err = read_recent_lines(log_path, window_minutes=5)
        if err or recent is None:
            continue
        for line in reversed(recent):
            m = MACHINE_LOADED_RE.search(line)
            if m:
                count = int(m.group(1))
                if count > 0:
                    print(f"   recovered: CAPE registered {count} machine(s)")
                    return True
    print("   [!] no machine-registration line appeared; recovery unconfirmed")
    return False


def reset_tasks(manifest_path, task_ids, note):
    """Return the affected samples to pending so a later batch resubmits them."""
    if not manifest_path or not os.path.exists(manifest_path):
        print(f"   [!] manifest not found: {manifest_path}")
        return 0
    if not task_ids:
        return 0

    with open(manifest_path, newline="") as f:
        rows = list(csv.DictReader(f))

    reset = 0
    for row in rows:
        tid = (row.get("cape_task_id") or "").strip()
        if tid and tid in task_ids:
            row["status"] = "pending"
            row["cape_task_id"] = ""
            row["result"] = ""
            row["notes"] = (row.get("notes", "") + f";{note}").strip(";")
            reset += 1

    if reset:
        with open(manifest_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDNAMES)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k, "") for k in MANIFEST_FIELDNAMES})
    return reset


def main():
    parser = argparse.ArgumentParser(
        description="Detect and recover from CAPE's stuck-machine failure mode.")
    parser.add_argument("--manifest", default=None,
                         help="Manifest CSV; affected tasks are set back to pending")
    parser.add_argument("--log", default=DEFAULT_LOG, help=f"CAPE log (default: {DEFAULT_LOG})")
    parser.add_argument("--service", default="cape", help="systemd unit name (default: cape)")
    parser.add_argument("--window", type=int, default=20, metavar="MINUTES",
                         help="How far back to look in the log (default: 20)")
    parser.add_argument("--fix", action="store_true",
                         help="Restart CAPE and reset affected tasks. Without this, "
                              "the script only reports what it found.")
    parser.add_argument("--wait", type=int, default=90, metavar="SECONDS",
                         help="How long to wait for machine re-registration (default: 90)")
    parser.add_argument("--state", default=DEFAULT_STATE,
                         help="State file used to enforce the restart cooldown")
    parser.add_argument("--force", action="store_true",
                         help="Ignore the restart cooldown")
    args = parser.parse_args()

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] CAPE health check (window: {args.window} min)")

    # Service state is reported for context only, never used to decide on a
    # restart. In the failure this script exists for, the service stayed
    # "active" for 33 hours straight while every task was being rejected --
    # only the machine registration had been lost. Acting on is-active would
    # therefore miss the real fault and could trigger restarts whenever the
    # status query itself fails.
    active = service_is_active(args.service)
    if active is False:
        print(f"   note: service {args.service} reports NOT active")
    elif active is None:
        print(f"   note: could not read {args.service} state")

    recent, err = read_recent_lines(args.log, args.window)
    if err:
        print(f"   [!] {err}")
        sys.exit(2)

    task_ids = detect_stuck_machine(recent)

    if not task_ids:
        print("   healthy: no unserviceable-task errors in the window")
        sys.exit(0)

    ordered = sorted(task_ids, key=lambda t: int(t))
    print(f"   PROBLEM: {len(task_ids)} task(s) failed with no available machine")
    print(f"   affected tasks: {ordered[0]}-{ordered[-1]}"
          if len(ordered) > 1 else f"   affected task: {ordered[0]}")

    if not args.fix:
        print("\n   --fix not given; no action taken.")
        print("   Re-run with --fix to restart CAPE and requeue the affected samples.")
        sys.exit(1)

    # Cooldown: a fault that survives a restart should not trigger endless
    # restarts, which would keep CAPE from ever finishing startup.
    state = load_state(args.state)
    last = state.get("last_restart", 0)
    since = time.time() - last
    if since < RESTART_COOLDOWN_SECONDS and not args.force:
        remaining = int(RESTART_COOLDOWN_SECONDS - since)
        print(f"\n   cooldown active: last restart was {int(since)}s ago, "
              f"waiting {remaining}s more")
        print("   (the fault persisted through a restart -- worth investigating "
              "manually; use --force to override)")
        sys.exit(1)

    print()
    recovered = restart_cape(args.service, args.log, args.wait)
    state["last_restart"] = time.time()
    state["last_restart_iso"] = stamp
    save_state(args.state, state)

    if args.manifest and task_ids:
        n = reset_tasks(args.manifest, task_ids, "cape_machine_unavailable")
        print(f"   requeued {n} sample(s) as pending")
        if n < len(task_ids):
            print(f"   ({len(task_ids) - n} affected task(s) had no manifest entry)")

    sys.exit(0 if recovered else 1)


if __name__ == "__main__":
    main()
