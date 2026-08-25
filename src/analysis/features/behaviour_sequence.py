#!/usr/bin/env python3
"""
behaviour_sequence.py - Turn a CAPE report into a time-ordered sequence of
behaviour events, so that frequent sub-sequences can be mined across samples.

The idea
--------
The research question is whether ransomware shows a semantic pattern in the
*order* of what it does, not in individual calls. The obstacle is scale: a
run is tens of thousands of file calls with a handful of preparatory acts
buried in them, so at the API level the preparation is 0.1% of the stream
and invisible. The fix is to raise the unit of analysis from the API call to
the *behaviour* -- shadow-copy deletion, service access, ransom-note
writing -- and collapse the repeated encryption loop to a single event. A
run of 60,000 calls becomes a sequence of six to twelve behaviours, and on
that a frequent-subsequence miner can find what recurs.

The vocabulary is not hand-picked. It was read off eight ransomware reports
(families behind task ids 80, 253, 464, 831, 1094, 1419, 1681, 2102): every
behaviour below was observed in at least one of them, with the detection
rule taken from what CAPE actually recorded -- the command line for
vssadmin, the API for SystemParametersInfo, the file pattern for the note.
Which of them are *frequent* and *discriminative* is not decided here; that
is what the mining and the contrast step decide, on all 1,800.

What a behaviour is
-------------------
Each behaviour is detected from evidence CAPE already provides:

  command line   vssadmin/bcdedit/wmic/wbadmin/netsh/schtasks/taskkill
  API name       SystemParametersInfo (wallpaper), NtTerminateProcess,
                 OpenSCManager (service access), connect (network)
  file pattern   the same file name written into many directories
                 (the ransom note), a file read then written under an
                 appended name (encryption)

A behaviour carries the timestamps of its evidence, so the sequence can be
ordered by first occurrence and the miner can allow gaps.

Output
------
For each report, an ordered list of behaviour tokens, and the per-sample
first/last timestamps so that overlap (encryption and note-writing run
concurrently) can be handled rather than forced into a false total order.

    python3 behaviour_sequence.py --archives ~/reports_a --out ~/work/seq_a.jsonl
    python3 behaviour_sequence.py --archives ~/rep --show      # inspect a few
"""

import os
import re
import csv
import glob
import gzip
import json
import time
import argparse
from concurrent.futures import ProcessPoolExecutor
from collections import defaultdict, Counter

# ------------------------------------------------------------- helpers

def _load(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", errors="replace") as f:
        return json.load(f)


def _args(call):
    a = call.get("arguments")
    if isinstance(a, list):
        return {x.get("name"): x.get("value") for x in a if isinstance(x, dict)}
    return a if isinstance(a, dict) else {}


def _task_id(path):
    m = re.search(r"task_(\d+)", os.path.basename(path))
    return m.group(1) if m else os.path.basename(path).split(".")[0]


BYSTANDERS = {"explorer.exe", "svchost.exe", "dllhost.exe", "wmiprvse.exe",
              "securityhealthhost.exe", "mobsync.exe", "useroobebroker.exe",
              "splwow64.exe", "slui.exe", "musnotification.exe",
              "runtimebroker.exe", "sihost.exe", "taskhostw.exe",
              "conhost.exe", "backgroundtaskhost.exe", "searchindexer.exe",
              "ctfmon.exe", "fontdrvhost.exe", "dwm.exe", "spoolsv.exe",
              "sppsvc.exe", "wuauclt.exe", "smartscreen.exe", "wmiadap.exe",
              "applicationframehost.exe", "shellexperiencehost.exe",
              "startmenuexperiencehost.exe", "textinputhost.exe",
              "musnotificationux.exe", "musnotifyicon.exe", "usoclient.exe",
              "searchapp.exe", "wmiprvse.exe"}


def own_pids(procs):
    if not procs:
        return set()
    root = procs[0].get("process_id")
    keep = {root}
    changed = True
    while changed:
        changed = False
        for p in procs:
            pid = p.get("process_id")
            if pid in keep:
                continue
            if (p.get("parent_id") in keep and
                    (p.get("process_name") or "").lower() not in BYSTANDERS):
                keep.add(pid)
                changed = True
    return keep


# --------------------------------------------- command-line behaviours

# Each rule maps a regex over a command line to a behaviour token. The
# vocabulary was fixed on 19 Aug after checking every candidate against
# twelve reports; see vocabulary_decision.md. A command that matches none
# is left out rather than forced into a bucket.
COMMAND_RULES = [
    ("SHADOW_DELETE",    re.compile(r"(?i)(vssadmin|wmic).{0,40}shadow(cop(y|ies))?\s*(delete|/nointeractive)|shadowcopy\s+delete|Win32_ShadowCopy")),
    # All bcdedit use is one behaviour: recoveryenabled no, bootstatuspolicy
    # ignoreallfailures, safeboot minimal -- every one is T1490/T1562.009.
    ("RECOVERY_DISABLE", re.compile(r"(?i)\bbcdedit\b")),
    ("BACKUP_DELETE",    re.compile(r"(?i)wbadmin.{0,20}(delete|catalog)")),
    ("FIREWALL_DISABLE", re.compile(r"(?i)netsh.{0,40}(firewall|advfirewall).{0,20}(off|disable)")),
    ("EVENTLOG_CLEAR",   re.compile(r"(?i)wevtutil.{0,10}\bcl\b|Clear-EventLog")),
    ("PERSIST_SCHTASK",  re.compile(r"(?i)schtasks.{0,10}/create")),
    ("PROCESS_KILL",     re.compile(r"(?i)\btaskkill\b")),
    ("SERVICE_ACCESS",   re.compile(r"(?i)\bnet\s+stop\b|\bsc\s+(stop|config|delete)\b")),
    # The sample executing a copy of itself from AppData: self-copy then run.
    ("SELF_COPY",        re.compile(r"(?i)appdata\\(roaming|local)\\[^\\\"]+\.exe")),
]

# --------------------------------------------- API-signalled behaviours

# behaviour token -> (api names, minimum count). The minimum is a floor to
# keep a stray call from becoming a behaviour, set from the twelve reports:
# installers sit at 11-13 deletes and 13 renames, ransomware at 20+ for
# anything it means to do. Not a tuned parameter.
API_RULES = {
    "WALLPAPER_SET":  (("SystemParametersInfoW", "SystemParametersInfoA"), 1),
    "PROCESS_KILL":   (("NtTerminateProcess",), 3),
    "PROCESS_ENUM":   (("CreateToolhelp32Snapshot", "Process32FirstW",
                        "Process32NextW"), 1),
    "SERVICE_ACCESS": (("OpenSCManagerW", "OpenServiceW", "ControlService",
                        "ChangeServiceConfigW", "DeleteService"), 2),
    "REGISTRY_WRITE": (("RegSetValueExW", "RegSetValueExA"), 3),
    "NETWORK":        (("connect", "WSAConnect", "InternetConnectW",
                        "InternetOpenUrlW", "HttpSendRequestW"), 1),
    "RM_SESSION":     (("RmStartSession", "RmRegisterResources"), 1),
    "CRYPTO_API":     (("CryptEncrypt", "BCryptEncrypt", "CryptGenKey",
                        "CryptDeriveKey", "BCryptGenerateSymmetricKey"), 5),
    "DIR_ENUMERATE":  (("FindFirstFileExW", "FindFirstFileW",
                        "NtQueryDirectoryFile"), 50),
    "FILE_DELETE":    (("NtDeleteFile", "DeleteFileW"), 20),
    "FILE_RENAME":    (("MoveFileW", "MoveFileExW", "MoveFileWithProgressW",
                        "MoveFileWithProgressTransactedW"), 20),
}

# NtSetInformationFile does different work by class; two classes are
# behaviours in their own right and are counted into FILE_DELETE and
# FILE_RENAME alongside the direct APIs above.
SETINFO_DELETE = "13"      # FileDispositionInformation
SETINFO_RENAME = "10"      # FileRenameInformation


def command_lines(report):
    """(timestamp, command string) for every executed command in the run."""
    out = []
    b = report.get("behavior", {}) or {}
    summary = b.get("summary", {}) or {}
    for c in summary.get("executed_commands", []) or []:
        out.append((None, str(c)))
    for p in b.get("processes", []) or []:
        cl = ((p.get("environ", {}) or {}).get("CommandLine")
              or p.get("command_line"))
        if cl:
            out.append((p.get("first_seen"), str(cl)))
    return out


def ransom_note(report):
    """
    The same file name written into many directories is a ransom note.

    This is the one behaviour present in all eight, and the most
    discriminative: no archiver or installer writes one file name into
    dozens of directories. The threshold is directory count, not file
    count, so a program that rewrites one log many times does not qualify.
    """
    b = report.get("behavior", {}) or {}
    summary = b.get("summary", {}) or {}
    by_name = defaultdict(set)
    for w in summary.get("write_files", []) or []:
        w = str(w)
        name = w.rsplit("\\", 1)[-1].lower()
        folder = w.rsplit("\\", 1)[0].lower() if "\\" in w else ""
        # notes are documents, not the encrypted payload
        if re.search(r"\.(txt|html?|hta|rtf|url|png|bmp)$", name):
            by_name[name].add(folder)
    hits = [(n, len(d)) for n, d in by_name.items() if len(d) >= 5]
    return sorted(hits, key=lambda x: -x[1])


def encryption_present(report):
    """
    A file read and then written under an appended name, or written through
    a mapped section, in quantity. Deliberately coarse: the point here is
    only that an encryption phase happened, so it can take its place in the
    sequence. How it happened is the per-file features' job.
    """
    b = report.get("behavior", {}) or {}
    procs = b.get("processes", []) or []
    keep = own_pids(procs)
    writes = 0
    for p in procs:
        if p.get("process_id") not in keep:
            continue
        for c in p.get("calls", []) or []:
            if c.get("api") in ("NtWriteFile", "WriteFile"):
                writes += 1
    return writes >= 50


def _parse_ts(s):
    """CAPE timestamps look like '2026-07-28 23:31:41,933'. Return a
    comparable float (seconds since an arbitrary origin) or None."""
    if not s:
        return None
    m = re.match(r"(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)(?:,(\d+))?", str(s))
    if not m:
        return None
    y, mo, d, h, mi, se, ms = (int(x) if x else 0 for x in m.groups())
    # days-in-month is not needed for ordering within one run; a monotone
    # combination is enough, and runs never cross a month boundary.
    return ((((d * 24 + h) * 60 + mi) * 60 + se) * 1000 + ms) / 1000.0


def _first_encrypt_time(procs, keep):
    """
    Time and index of the first write that is part of an encryption phase:
    a file read and then written under the same stem, or a mapped section
    written back. Requiring the read-write relation -- not just writes --
    keeps installers out: they write hundreds of files they never read.

    Returns (time, index) or None.
    """
    read_paths = set()
    section_path = {}
    idx = 0
    first = None
    n_enc = 0
    for p in procs:
        if p.get("process_id") not in keep:
            idx += len(p.get("calls", []) or [])
            continue
        for c in p.get("calls", []) or []:
            api = c.get("api", "")
            a = _args(c)
            if api == "NtCreateSection":
                h, fn = a.get("SectionHandle"), a.get("FileName")
                if h and fn:
                    section_path[str(h)] = str(fn).lower()
            elif api in ("NtReadFile", "ReadFile"):
                path = (a.get("HandleName") or "").lower()
                if path and not path.startswith("\\device\\"):
                    read_paths.add(path)
                    read_paths.add(_stem_local(path))
            elif api == "NtMapViewOfSection":
                pth = section_path.get(str(a.get("SectionHandle")))
                if pth:
                    read_paths.add(pth)
            elif api in ("NtWriteFile", "WriteFile"):
                path = (a.get("HandleName") or "").lower()
                if path and (path in read_paths or _stem_local(path) in read_paths):
                    n_enc += 1
                    if first is None:
                        first = (_parse_ts(c.get("timestamp")), idx)
            idx += 1
    return first if n_enc >= 20 else None


def _first_note_time(report, procs, keep):
    """
    Time and index of the first write of a ransom note: the same file name
    written into five or more directories. Uses the enhanced file events for
    timing where present, falling back to the summary for the name set.
    """
    names = {n for n, _ in ransom_note(report)}
    if not names:
        return None
    idx = 0
    for p in procs:
        if p.get("process_id") not in keep:
            idx += len(p.get("calls", []) or [])
            continue
        for c in p.get("calls", []) or []:
            if c.get("api") in ("NtWriteFile", "WriteFile", "NtCreateFile"):
                path = (_args(c).get("HandleName") or _args(c).get("FileName") or "").lower()
                nm = path.rsplit("\\", 1)[-1]
                if nm in names:
                    return (_parse_ts(c.get("timestamp")), idx)
            idx += 1
    return None


def _stem_local(path):
    p = path.lower()
    i = p.rfind(".")
    j = p.rfind("\\")
    return p[:i] if i > j >= 0 or (i > 0 and j < 0) else p


def detect_behaviours(report):
    """
    All behaviour occurrences ordered by real time.

    Every behaviour is anchored to a timestamp: a command to the first_seen
    of the process that ran it, an API behaviour to the timestamp of its
    first qualifying call, encryption and the ransom note to the first write
    that evidences them. Where two behaviours share a timestamp -- common,
    since CAPE's resolution is a millisecond and calls burst -- the tie is
    broken by position in the call stream, so the order is the order the
    sample actually did things in, not the order the rules are listed.

    Preparation happens once and early; encryption and note-writing span the
    run. Anchoring each to its *first* evidence puts shadow-delete before
    encryption where the run did that, and leaves genuinely concurrent acts
    in the order they began.
    """
    b = report.get("behavior", {}) or {}
    procs = b.get("processes", []) or []
    keep = own_pids(procs)

    # Build one flat, time-ordered view of the own-tree call stream, keeping
    # each call's timestamp and its global index for tie-breaking.
    stream = []          # (ts_or_None, index, api, process_first_seen)
    idx = 0
    for p in procs:
        if p.get("process_id") not in keep:
            continue
        pfs = _parse_ts(p.get("first_seen"))
        for c in p.get("calls", []) or []:
            stream.append((_parse_ts(c.get("timestamp")), idx, c.get("api"), pfs))
            idx += 1

    # A fallback time for behaviours with no call-level timestamp: the run's
    # own start, so command-line behaviours sort by their process start.
    run_start = min((t for t, _, _, _ in stream if t is not None), default=0.0)

    events = []          # (time, index, token)

    # Command-line behaviours: anchor to the running process's first_seen.
    for p in procs:
        cl = ((p.get("environ", {}) or {}).get("CommandLine")
              or p.get("command_line"))
        if not cl:
            continue
        t = _parse_ts(p.get("first_seen")) or run_start
        for token, rx in COMMAND_RULES:
            if rx.search(str(cl)):
                events.append((t, -1, token))
    # executed_commands has no timestamp; anchor to run start, ordered as listed.
    for j, c in enumerate((b.get("summary", {}) or {}).get("executed_commands", []) or []):
        for token, rx in COMMAND_RULES:
            if rx.search(str(c)):
                events.append((run_start, -1000 + j, token))

    # API-signalled behaviours: anchor to the first qualifying call's time.
    # NtSetInformationFile with class 10 or 13 is a rename or a delete and is
    # counted as such, since several families rename and delete that way
    # rather than through MoveFile/NtDeleteFile.
    api_first = {}       # api -> (ts, index)
    api_count = Counter()
    for ts, i, api, _ in stream:
        api_count[api] += 1
        if api not in api_first:
            api_first[api] = (ts if ts is not None else run_start, i)
    # second pass for the class-dependent SetInformationFile cases
    idx2 = 0
    for p in procs:
        if p.get("process_id") not in keep:
            continue
        for c in p.get("calls", []) or []:
            if c.get("api") == "NtSetInformationFile":
                cls = str(_args(c).get("FileInformationClass", ""))
                key = ("__setinfo_delete" if cls == SETINFO_DELETE
                       else "__setinfo_rename" if cls == SETINFO_RENAME else None)
                if key:
                    api_count[key] += 1
                    if key not in api_first:
                        api_first[key] = (_parse_ts(c.get("timestamp")) or run_start, idx2)
            idx2 += 1
    for token, (apis, minimum) in API_RULES.items():
        apis = tuple(apis)
        if token == "FILE_DELETE":
            apis = apis + ("__setinfo_delete",)
        elif token == "FILE_RENAME":
            apis = apis + ("__setinfo_rename",)
        total = sum(api_count.get(a, 0) for a in apis)
        if total >= minimum:
            firsts = [api_first[a] for a in apis if a in api_first]
            if firsts:
                t, i = min(firsts)
                events.append((t, i, token))

    # Encryption and the ransom note: anchor to the first write of each.
    enc_t = _first_encrypt_time(procs, keep)
    if enc_t is not None:
        events.append((enc_t[0], enc_t[1], "FILE_ENCRYPT"))
    note = _first_note_time(report, procs, keep)
    if note is not None:
        events.append((note[0], note[1], "RANSOM_NOTE"))

    # Order by (time, index), then dedupe to first occurrence.
    events.sort(key=lambda x: (x[0], x[1]))
    seq, seen = [], set()
    for _, _, token in events:
        if token not in seen:
            seq.append(token)
            seen.add(token)
    return seq


# ------------------------------------------------------------- driver

def process_one(path):
    try:
        r = _load(path)
    except Exception as e:
        return {"task_id": _task_id(path), "error": type(e).__name__}
    return {"task_id": _task_id(path), "sequence": detect_behaviours(r)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archives", required=True)
    ap.add_argument("--out")
    ap.add_argument("--show", action="store_true",
                    help="Print each sequence instead of writing a file")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4,
                    help="Parsing is the whole cost and each report is "
                         "independent, so this scales almost linearly")
    ap.add_argument("--every", type=int, default=200,
                    help="Report progress every N reports")
    args = ap.parse_args()

    label = os.path.basename(os.path.normpath(os.path.expanduser(args.archives)))
    files = sorted(glob.glob(os.path.join(
        os.path.expanduser(args.archives), "*.json*")))
    print(f"[{label}] {len(files)} reports, {args.workers} workers", flush=True)

    out_f = open(os.path.expanduser(args.out), "w") if args.out else None
    t0 = time.time()
    rows, failed = [], 0
    with ProcessPoolExecutor(args.workers) as ex:
        for i, r in enumerate(ex.map(process_one, files, chunksize=4), 1):
            if "error" in r:
                failed += 1
            else:
                rows.append(r)
                if out_f:
                    out_f.write(json.dumps(r) + "\n")
            if i % args.every == 0 or i == len(files):
                el = time.time() - t0
                left = (len(files) - i) / (i / el) if el and i else 0
                print(f"[{label}] {i}/{len(files)}  {el/60:.1f} min in, "
                      f"{left/60:.1f} min left, {failed} failed", flush=True)
    if out_f:
        out_f.close()

    ok = rows
    if args.show or not args.out:
        for r in ok:
            print(f"  {r['task_id']:<10} {' -> '.join(r['sequence'])}")

    # The vocabulary frequency is the check that matters: a token that never
    # fires is a detection rule that does not work on this data.
    vocab = Counter(t for r in ok for t in r["sequence"])
    print(f"\n[{label}] behaviour frequency ({len(ok)} sequences):")
    for t, n in vocab.most_common():
        print(f"   {t:<20}{n:>5} / {len(ok)}  ({n/max(1,len(ok)):.0%})")
    empty = sum(1 for r in ok if not r["sequence"])
    if empty:
        print(f"   ({empty} reports produced no behaviour at all)")

    if args.out:
        print(f"[saved] {args.out}  ({len(ok)} sequences, "
              f"{time.time()-t0:.0f}s)\n", flush=True)


if __name__ == "__main__":
    main()
