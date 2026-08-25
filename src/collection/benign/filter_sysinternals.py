#!/usr/bin/env python3
"""
filter_sysinternals.py - Move aside the tools that would damage the analysis.

Most of the suite is safe to run: it reports on the system and changes
nothing. A handful are not, and submitting them costs more than the sample
is worth.

The dangerous group
-------------------
notmyfault exists to crash the kernel. That is its entire purpose -- it is
shipped so that administrators can produce a crash dump on demand. Run in the
guest it produces a bluescreen, the analysis ends without a report, and the
machine has to be reverted before the next sample, which is the failure that
cost several hours when the host network went down mid-batch.

Testlimit exhausts handles, memory or processes until something gives.
CPUSTRES saturates every core, which does not crash anything but makes every
timing feature in the run meaningless.

The persistent group
--------------------
Sysmon, Procmon and ctrl2cap install kernel drivers. A snapshot revert should
undo that, but the guest is the one piece of this setup that cannot easily be
rebuilt, and a driver that fails to unload leaves it in a state where later
analyses differ from earlier ones for reasons nothing to do with the samples.

psshutdown reboots. Autologon rewrites stored credentials. Volumeid changes
the volume serial, which several families read as part of deciding whether
they are in a sandbox.

The impractical group
---------------------
disk2vhd images the entire disk, which will not finish inside ten minutes and
would fill the analysis storage if it did. RDCMan is 73 MB and ZoomIt 16 MB
of GUI that does nothing without interaction.

Everything else is kept. A tool that prints its usage and exits is still a
data point -- it is a signed Microsoft binary that did almost nothing, which
is the same shape as most of the benign set and worth having for comparison.

Usage
-----
  python3 filter_sysinternals.py --dir ~/hn2/sysinternals
"""

import os
import csv
import shutil
import argparse

# Matched case-insensitively against the filename without its extension, so
# that both the 32- and 64-bit builds of each are caught.
UNSAFE = {
    # crashes or hangs the guest
    "notmyfault": "deliberately crashes the kernel",
    "notmyfaultc": "deliberately crashes the kernel",
    "testlimit": "exhausts handles, memory or processes",
    "cpustres": "saturates every core, ruining the timing features",
    # changes the guest in ways a revert may not undo cleanly
    "sysmon": "installs a kernel driver and a service",
    "procmon": "installs a kernel driver",
    "ctrl2cap": "installs a keyboard filter driver",
    "livekd": "kernel debugger",
    "psshutdown": "reboots or shuts down",
    "autologon": "rewrites stored credentials",
    "volumeid": "changes the volume serial, which families read as a sandbox cue",
    # will not finish, or has nothing to do without a user
    "disk2vhd": "images the whole disk",
    "rdcman": "73 MB of GUI",
    "rdcman-x86": "67 MB of GUI",
    "zoomit": "screen annotation, needs a user",
}


def base_of(filename):
    stem = os.path.splitext(filename)[0].lower()
    return stem[:-2] if stem.endswith("64") else stem


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True)
    parser.add_argument("--into", default=None,
                         help="Where to move them; defaults to a sibling "
                              "directory named after the source")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    src = os.path.expanduser(args.dir)
    dst = args.into or (src.rstrip("/") + "_excluded")
    dst = os.path.expanduser(dst)

    files = sorted(f for f in os.listdir(src) if f.lower().endswith(".exe"))
    moved, kept = [], []
    for f in files:
        reason = UNSAFE.get(base_of(f))
        (moved if reason else kept).append((f, reason))

    print(f"{len(files)} executables")
    print(f"   keep    {len(kept)}")
    print(f"   exclude {len(moved)}")
    print()
    for f, reason in moved:
        print(f"   {f:<24}{reason}")

    if args.dry_run:
        print("\ndry run; nothing moved")
        return

    os.makedirs(dst, exist_ok=True)
    for f, _ in moved:
        shutil.move(os.path.join(src, f), os.path.join(dst, f))

    # The manifest has to follow, or the excluded tools reappear as rows with
    # no analysis behind them.
    manifest = os.path.join(src, "installer_manifest.csv")
    if os.path.exists(manifest):
        rows = list(csv.DictReader(open(manifest, newline="")))
        excluded = {f for f, _ in moved}
        remaining = [r for r in rows if r["filename"] not in excluded]
        with open(manifest, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(remaining)
        print(f"\nmanifest trimmed to {len(remaining)} rows")

    print(f"\n{len(moved)} moved to {dst}")
    print(f"{len(kept)} remain in {src}")


if __name__ == "__main__":
    main()
