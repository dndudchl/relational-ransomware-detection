#!/usr/bin/env python3
"""
extract_features.py - Extract dynamic AND static features from a CAPE
analysis in one pass, writing a single row per sample.

This merges what used to be two separate tools:
  1. correlate.py      -- dynamic behavioral features (file lifecycle,
                          write<->crypto time correlation)
  2. static_imports.py -- static PE import categories

They are merged because a single CAPE report.json already contains both:
`behavior` (what the sample did) and `static` (what the binary is). Reading
the report once and emitting one combined row keeps the feature table
consistent and avoids re-parsing large reports twice.

Merging also unlocks a feature class that neither tool could compute
alone: static<->dynamic interaction. For example, a sample that imports
CryptEncrypt but never calls it at runtime either failed to trigger or
bypassed the Windows crypto API with its own implementation. That
disagreement between "what it was built to do" and "what it actually did"
is itself a signal, and it is only visible when both views are combined.

Feature groups emitted
----------------------
  identity   : sample_id, sha256, label, family, source
  dynamic    : file lifecycle counts and ratios, windowed chain metrics,
               write<->crypto Pearson correlation
  static     : PE import category counts, indicative_category_count,
               statically-linked crypto library fingerprints
  interaction: agreement/disagreement between static intent and dynamic
               behavior

Usage
-----
  # Single analysis
  python3 extract_features.py /opt/CAPEv2/storage/analyses/37 \\
      --features-out ../../../data/features.csv --label ransomware

  # Every analysis that passed analyze_result.py
  python3 extract_features.py --batch /opt/CAPEv2/storage/analyses \\
      --results analysis_results.csv --keep-verdict TRUE_ENCRYPTION \\
      --features-out ../../../data/features.csv \\
      --manifest ../../../data/manifests/manifest_all.csv
"""

import os
import sys
import re
import gzip
import json
import csv
import math
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ---------------- Dynamic config ----------------

TS_FORMAT = "%Y-%m-%d %H:%M:%S,%f"
FILE_EVENT_TYPES = ["read", "write", "delete", "move", "copy", "execute"]
DESTRUCTIVE_EVENT_TYPES = ["delete", "move"]

# ---------------- Preparation behaviour ----------------
#
# Before encrypting, ransomware typically clears the ground: it deletes volume
# shadow copies so files cannot be rolled back, disables Windows recovery,
# and stops database, backup and mail services so their files are not held
# open. Task 81 in this dataset did exactly this -- taskkill followed by
# net stop on SQL services -- and then stopped, having prepared but never
# encrypted.
#
# These are measured, not used in the verdict. On their own they show intent
# rather than outcome, and treating intent as outcome would have counted that
# run as a successful encryption. They are recorded because a detector that
# only fires once files are already encrypted is of limited use, whereas
# preparation happens beforehand.
#
# The counts alone are weak signals: installers stop services, backup tools
# touch shadow copies, cleanup utilities kill processes. What distinguishes
# ransomware is the sequence -- preparation followed shortly by mass file
# destruction -- which is why the delay between the two is measured as well.
# None of this can be trusted until the benign control set has been run
# through the sandbox for comparison.
COMMAND_PATTERNS = {
    "shadow_delete": ["vssadmin", "shadowcopy", "wbadmin", "delete shadows",
                       "delete catalog", "resize shadowstorage"],
    "recovery_disable": ["bcdedit", "recoveryenabled", "bootstatuspolicy",
                          "ignoreallfailures"],
    "service_stop": ["net stop", "sc stop", "sc.exe stop", "net1 stop"],
    "process_kill": ["taskkill", "tskill", "wmic process call terminate"],
    "log_clear": ["wevtutil", "clear-eventlog", "cipher /w"],
}


# Utilities whose launch is itself the act. Matching on the process name
# rather than the command line is what makes these usable for timing: the
# command list carries no timestamps, while every process records when it
# started.
#
# It also sidesteps an evasion seen in the data. One sample invoked
# "C:\fqkq\..\Windows\yaxq\qp\d\..\..\..\system32\lu\n\..\..\wbem\cl\oj\..\..\wmic.exe
# shadowcopy delete" -- padding the path with fake directories and traversals
# to defeat exact-path matching. The process name survives that intact.
PREPARATION_PROCESSES = {
    "vssadmin.exe": "shadow",
    "wmic.exe": "shadow",          # almost always "shadowcopy delete" in this set
    "wbadmin.exe": "shadow",
    "bcdedit.exe": "recovery",
    "net.exe": "service",
    "net1.exe": "service",
    "sc.exe": "service",
    "taskkill.exe": "kill",
    "wevtutil.exe": "logs",
    "schtasks.exe": "persistence",
    "reg.exe": "persistence",
}


def preparation_process_times(report):
    """
    When each ground-clearing utility was launched.

    Returns a list of (timestamp, category), sorted.
    """
    out = []
    for process in report.get("behavior", {}).get("processes", []) or []:
        name = (process.get("process_name") or "").lower()
        category = PREPARATION_PROCESSES.get(name)
        if not category:
            continue
        ts = parse_ts(process.get("first_seen"))
        if ts:
            out.append((ts, category))
    return sorted(out)


def extract_preparation_features(report, lifecycle_events):
    """
    Ground-clearing activity, and how long before the first file was destroyed
    it happened.

    The delay is the relational part. A count of service stops says only that
    services were stopped; a service stopped forty seconds before a thousand
    files start being rewritten says something the counts cannot.
    """
    behavior = report.get("behavior", {}) or {}
    summary = behavior.get("summary", {}) or {}

    commands = [c for c in (summary.get("executed_commands") or []) if isinstance(c, str)]
    joined = [c.lower() for c in commands]

    features = {"n_executed_commands": len(commands)}
    for name, patterns in COMMAND_PATTERNS.items():
        features[f"n_{name}"] = sum(
            1 for c in joined if any(pat in c for pat in patterns))

    features["n_services_created"] = len(summary.get("created_services") or [])
    features["n_services_started"] = len(summary.get("started_services") or [])
    features["n_registry_writes"] = len(summary.get("write_keys") or [])
    features["n_registry_deletes"] = len(summary.get("delete_keys") or [])

    # Timed preparation events. Service manipulation is rare enough to be
    # meaningful on its own; registry writes number in the thousands and are
    # dominated by ordinary process startup, so they are counted but not used
    # as the reference point.
    prep_times = []
    for event in behavior.get("enhanced", []) or []:
        if event.get("object") != "service":
            continue
        ts = parse_ts(event.get("timestamp"))
        if ts:
            prep_times.append(ts)

    destroy_times = [ts for ts, et, _ext, _p in lifecycle_events
                     if et in DESTRUCTIVE_EVENT_TYPES or et == "write"]

    if prep_times and destroy_times:
        delay = (min(destroy_times) - min(prep_times)).total_seconds()
        features["prep_to_destroy_delay_sec"] = round(delay, 1)
        features["n_service_events"] = len(prep_times)
    else:
        features["prep_to_destroy_delay_sec"] = ""
        features["n_service_events"] = len(prep_times)

    # ---- ordering between preparation and destruction ----
    #
    # This is the part the counts cannot express. Backup software touches
    # volume shadow copies; so does ransomware. What separates them is not
    # the act but what follows it, and how soon.
    #
    # Recorded here: whether preparation happened at all, whether destruction
    # followed it, how much preparation preceded the first destroyed file,
    # and the gap between the two. A tool that deletes shadow copies and then
    # does nothing scores zero on everything except the count.
    prep_processes = preparation_process_times(report)
    features["n_prep_processes"] = len(prep_processes)
    features["n_prep_categories"] = len({c for _ts, c in prep_processes})

    # What follows preparation has to be destruction, not merely file writing.
    # Backup and archiving tools touch shadow copies too and then write their
    # output; measured against writes, they look identical to ransomware.
    # Deletes and renames are the part they do not do.
    hard_destroy_times = sorted(ts for ts, et, _ext, _p in lifecycle_events
                                 if et in DESTRUCTIVE_EVENT_TYPES)
    destroy_times = hard_destroy_times

    if not prep_processes or not destroy_times:
        features["prep_to_first_destroy_sec"] = ""
        features["n_prep_before_destroy"] = "" if not prep_processes else 0
        features["prep_precedes_destroy"] = ""
        return features

    first_destroy = min(destroy_times)
    before = [ts for ts, _c in prep_processes if ts <= first_destroy]

    features["n_prep_before_destroy"] = len(before)
    # Measured, this predicts the opposite of what it was built to capture.
    # Among runs of 25k-75k API calls, 69% of those that did NOT encrypt had
    # prepared before their first destructive event, against 23% of those
    # that did -- a 46-point gap over 1,035 runs.
    #
    # The reason is that encryption and preparation run concurrently, so a
    # run that encrypts is already destroying files when its preparation
    # starts. A run that stops short destroys only incidentally, and those
    # few events necessarily come later. The feature therefore reads closer
    # to "was destruction incidental" than to "did preparation come first",
    # and a model given it will learn that preparing first means not
    # encrypting.
    features["prep_precedes_destroy"] = int(bool(before))
    features["prep_to_first_destroy_sec"] = (
        round((first_destroy - min(before)).total_seconds(), 1) if before else "")

    # How much destruction followed, and over how long. Preparation followed
    # by two deletions is a different claim from preparation followed by a
    # thousand, and the ordering alone does not say which happened.
    features["n_destroy_after_prep"] = sum(1 for ts in destroy_times
                                            if before and ts >= min(before))

    last_destroy = max(destroy_times)
    features["destroy_span_after_prep_sec"] = (
        round((last_destroy - first_destroy).total_seconds(), 1)
        if len(destroy_times) > 1 else 0.0)

    # Overlap, rather than precedence.
    #
    # The features above were written expecting ransomware to clear the ground
    # and then begin encrypting. Measured, that is not what happens. Among
    # runs that did both, the median gap between the first preparation tool
    # and the first destroyed file is 1.7 seconds, and only 19% launched a
    # preparation tool before destruction had already started. Encryption and
    # shadow-copy deletion run at the same time, on separate threads.
    #
    # So "did preparation come first" is close to a coin toss and says little.
    # What does hold is that the two happen together: preparation falls inside
    # the window during which files are being destroyed. A backup tool that
    # touches shadow copies has no such window to fall inside.
    prep_times = [ts for ts, _c in prep_processes]
    inside = [ts for ts in prep_times if first_destroy <= ts <= last_destroy]
    features["n_prep_during_destroy"] = len(inside)
    features["prep_overlaps_destroy"] = int(bool(inside or before))

    # Where preparation sits within the destruction window, as a fraction:
    # 0 means it began with the destruction, 1 means it came at the very end.
    span = (last_destroy - first_destroy).total_seconds()
    if inside and span > 0:
        offsets = [(ts - first_destroy).total_seconds() / span for ts in inside]
        features["prep_position_in_destroy"] = round(min(offsets), 3)
    else:
        features["prep_position_in_destroy"] = ""

    return features


# ---------------- Static config ----------------

IMPORT_CATEGORIES = {
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
        "CryptExportKey", "CryptAcquireContext", "CryptDestroyKey",
        "CryptReleaseContext", "CryptGenRandom", "BCryptEncrypt",
        "BCryptGenRandom", "CryptStringToBinary", "CryptImportPublicKeyInfo",
    ],
    "random": ["CryptGenRandom", "BCryptGenRandom", "RtlGenRandom", "rand_s"],
    "file_ops": [
        "CreateFileW", "CreateFileA", "WriteFile", "ReadFile",
        "DeleteFileW", "MoveFileW", "MoveFileExW", "CopyFileW",
        "SetFilePointerEx", "FindFirstFileExW", "FindNextFileW",
    ],
    "volume_enum": [
        "FindFirstVolumeW", "FindNextVolumeW", "GetDriveTypeW",
        "GetVolumePathNamesForVolumeNameW", "SetVolumeMountPointW",
    ],
    "network_spread": [
        "WNetOpenEnum", "WNetAddConnection", "WNetEnumResource", "WNetCloseEnum",
    ],
    "file_unlock": ["RmStartSession", "RmRegisterResources", "RmGetList", "RmEndSession"],
    "process_enum": [
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "OpenProcessToken", "AdjustTokenPrivileges",
    ],
    "shadow_service": ["DeleteFileW", "ControlService", "OpenSCManager", "OpenServiceW"],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "SetUnhandledExceptionFilter", "NtQueryInformationProcess",
    ],
}

CRYPTO_LIB_FINGERPRINTS = {
    "cryptopp": ["cryptopp", "CryptoPP", "rijndael_simd", "Crypto++"],
    "openssl": ["OpenSSL", "libcrypto", "SSLeay"],
    "mbedtls": ["mbedtls", "mbed TLS"],
    "libsodium": ["libsodium", "sodium_"],
    "wolfssl": ["wolfSSL", "wolfssl"],
    "boost": ["boost"],
}

INDICATIVE_CATEGORIES = ("crypto", "volume_enum", "network_spread",
                          "file_unlock", "process_enum")

# Below this many imports, the import table is effectively unreadable: the
# binary is packed or obfuscated and its declared imports say nothing about
# what it can do. Such rows still get written (so the dataset honestly
# records how many samples were unanalysable) but they are flagged, because
# their all-zero static features are an absence of evidence, not evidence of
# absence -- and our benign control set contains no packed programs, so a
# model would otherwise learn "no imports = ransomware" from a dataset
# artefact rather than from behaviour.
MIN_READABLE_IMPORTS = 20


# ---------------- Shared helpers ----------------

def parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(ts.strip(), TS_FORMAT)
    except (ValueError, TypeError):
        return None


def event_paths(event):
    """
    Paths involved in a file event.

    A move carries data.from and data.to rather than data.file, so reading
    only data.file silently discarded every move -- and renaming the original
    to an encrypted counterpart (file.docx -> file.docx.cipher4) is how
    several families encrypt. The source path is used, since that is the
    original file which ceased to exist.
    """
    data = event.get("data", {}) or {}
    single = data.get("file")
    if single:
        return [single]
    source = data.get("from")
    return [source] if source else []


def get_extension(path):
    if not path or "." not in path.split("\\")[-1]:
        return "(none)"
    return path.split(".")[-1].lower()


def pearson(xs, ys):
    n = len(xs)
    if n == 0:
        return None
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    dy = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if dx == 0 or dy == 0:
        return None
    return num / (dx * dy)


def shannon_entropy(byte_values):
    """
    Shannon entropy of a list of byte values, in bits (0-8).

    Encrypted output approaches 8.0 because every byte value becomes
    roughly equally likely. This matters beyond the crypto-API axis: a
    sample that encrypts without calling the Windows crypto API still
    produces high-entropy data, so entropy is a signal that survives
    custom / statically-linked crypto implementations.
    """
    if not byte_values:
        return 0.0
    freq = defaultdict(int)
    for b in byte_values:
        freq[b] += 1
    n = len(byte_values)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def decode_buffer(raw):
    """
    Approximately decode a CAPE buffer string (e.g. '\\xba\\xe1...') into a
    list of byte values. Best-effort approximation for entropy estimation,
    not a byte-exact decoder.
    """
    if not raw:
        return []
    out = []
    i = 0
    s = raw
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "x" and i + 3 < len(s):
                try:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            escape_map = {"n": 10, "r": 13, "t": 9, "v": 11, "\\": 92}
            out.append(escape_map.get(nxt, ord(nxt)))
            i += 2
            continue
        out.append(ord(s[i]) & 0xff)
        i += 1
    return out


# ---------------- Dynamic extraction ----------------

def extract_lifecycle_events(report):
    """(datetime, event_type, extension, path) for every file event."""
    events = []
    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type not in FILE_EVENT_TYPES:
            continue
        ts = parse_ts(event.get("timestamp"))
        if not ts:
            continue
        paths = event_paths(event)
        if not paths:
            # Keep the event so counts and ratios stay correct even when no
            # path could be resolved; extension-based features simply skip it.
            events.append((ts, event_type, "(none)", ""))
            continue
        for path in paths:
            events.append((ts, event_type, get_extension(path), path))
    return events


def extract_crypto_calls(report):
    """(datetime, length, entropy, api_name) for crypto-category API calls.

    The Buffer argument, when present, holds the data passed to the crypto
    API. Its entropy tells us whether real encryption output is flowing
    through, as opposed to the API merely being touched.
    """
    events = []
    for process in report.get("behavior", {}).get("processes", []) or []:
        for call in process.get("calls", []) or []:
            if call.get("category") != "crypto":
                continue
            ts = parse_ts(call.get("timestamp"))
            if not ts:
                continue
            length = 0
            buf = None
            args = call.get("arguments", [])
            if isinstance(args, list):
                for arg in args:
                    if arg.get("name") == "Length":
                        try:
                            length = int(arg.get("value", 0))
                        except (ValueError, TypeError):
                            length = 0
                    if arg.get("name") == "Buffer":
                        buf = arg.get("value")
            entropy = shannon_entropy(decode_buffer(buf)) if buf else 0.0
            events.append((ts, length, entropy, call.get("api", "?")))
    return events


def windowize_crypto(lifecycle_events, crypto_events, window_sec):
    """
    Bucket WRITE events and crypto calls into fixed windows, using a timeline
    defined by writes and crypto calls only.

    This deliberately uses a different time origin from the lifecycle
    windowing below. The write<->crypto correlation is a statement about
    those two series specifically, so its windows are anchored to the first
    write-or-crypto event. Anchoring it to the first file event of any kind
    (including reads that may precede any write) would shift every bucket
    boundary and change the correlation value.
    """
    writes = [(ts, et) for ts, et, _ext, _p in lifecycle_events if et == "write"]
    all_ts = [ts for ts, _et in writes] + [c[0] for c in crypto_events]
    if not all_ts:
        return [], []
    t0, t_end = min(all_ts), max(all_ts)
    n_buckets = int((t_end - t0).total_seconds() // window_sec) + 1

    write_series = [0] * n_buckets
    crypto_series = [0] * n_buckets

    for ts, _et in writes:
        write_series[int((ts - t0).total_seconds() // window_sec)] += 1
    for ts, _length, _entropy, _api in crypto_events:
        crypto_series[int((ts - t0).total_seconds() // window_sec)] += 1

    return write_series, crypto_series


def windowize_lifecycle(lifecycle_events, window_sec):
    """
    Bucket all file lifecycle events into fixed windows, anchored to the
    first file event. Used for the chain metrics below.
    """
    if not lifecycle_events:
        return []
    all_ts = [e[0] for e in lifecycle_events]
    t0, t_end = min(all_ts), max(all_ts)
    n_buckets = int((t_end - t0).total_seconds() // window_sec) + 1

    windows = [{t: 0 for t in FILE_EVENT_TYPES} for _ in range(n_buckets)]
    for ts, event_type, _ext, _path in lifecycle_events:
        windows[int((ts - t0).total_seconds() // window_sec)][event_type] += 1
    return windows


def compute_chain_metrics(lifecycle_windows):
    """
    Classify each active window:
      destructive_chain          - read + write + (delete or move) together
                                   (ransomware: read original, write encrypted,
                                   remove original)
      write_only_nondestructive  - writes without any delete/move
                                   (benign archiving: originals untouched)
    """
    active = destructive = write_only = other = 0
    for row in lifecycle_windows:
        if not any(row[t] > 0 for t in FILE_EVENT_TYPES):
            continue
        active += 1
        has_read = row["read"] > 0
        has_write = row["write"] > 0
        has_destructive = row["delete"] > 0 or row["move"] > 0
        if has_read and has_write and has_destructive:
            destructive += 1
        elif has_write and not has_destructive:
            write_only += 1
        else:
            other += 1
    return {
        "active_windows": active,
        "destructive_chain_windows": destructive,
        "write_only_nondestructive_windows": write_only,
        "other_windows": other,
    }


def extract_dynamic_features(report, window_sec):
    lifecycle_events = extract_lifecycle_events(report)
    crypto_events = extract_crypto_calls(report)

    counts = {t: 0 for t in FILE_EVENT_TYPES}
    for _ts, event_type, _ext, _path in lifecycle_events:
        counts[event_type] += 1

    writes = counts["write"]
    delete_ratio = counts["delete"] / writes if writes else ""
    move_ratio = counts["move"] / writes if writes else ""

    write_series, crypto_series = windowize_crypto(
        lifecycle_events, crypto_events, window_sec)
    lifecycle_windows = windowize_lifecycle(lifecycle_events, window_sec)
    chain = compute_chain_metrics(lifecycle_windows)
    corr = pearson(write_series, crypto_series)

    # Entropy of data passed through the crypto API. High values (near 8)
    # indicate genuine encryption output rather than incidental API use.
    entropies = [e for _ts, _len, e, _api in crypto_events if e > 0]
    entropy_mean = sum(entropies) / len(entropies) if entropies else ""
    entropy_max = max(entropies) if entropies else ""

    # Distinct extensions attacked -- a broad spread suggests indiscriminate
    # encryption rather than a program working with one file type.
    destructive_exts = {ext for _ts, et, ext, _p in lifecycle_events
                        if et in DESTRUCTIVE_EVENT_TYPES}

    return {
        "n_file_writes": counts["write"],
        "n_crypto_calls": len(crypto_events),
        "write_crypto_pearson": corr if corr is not None else "",
        "crypto_buffer_entropy_mean": entropy_mean,
        "crypto_buffer_entropy_max": entropy_max,
        "n_read": counts["read"],
        "n_write": counts["write"],
        "n_delete": counts["delete"],
        "n_move": counts["move"],
        "n_copy": counts["copy"],
        "n_execute": counts["execute"],
        "delete_to_write_ratio": delete_ratio,
        "move_to_write_ratio": move_ratio,
        "destructive_extension_variety": len(destructive_exts),
        **chain,
    }


# ---------------- Static extraction ----------------

def _flatten_import_container(container):
    """
    Both report formats end in the same per-DLL shape
    ({"dll": ..., "imports": [{"name": ...}]}), but wrap it differently:
      - CAPE:           a dict keyed by short DLL name
      - legacy Cuckoo:  a list of those per-DLL entries
    """
    entries = []
    if isinstance(container, dict):
        entries = list(container.values())
    elif isinstance(container, list):
        entries = container

    names = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for imp in entry.get("imports", []) or []:
            name = imp.get("name") if isinstance(imp, dict) else None
            if name:
                names.append(name)
    return names


def get_imports(report):
    """
    Imports declared by the SUBMITTED file.

    CAPE stores these under target.file.pe.imports; the older Cuckoo reports
    used static.pe_imports. We read whichever is present so the same feature
    definition applies to both datasets, and so these stay comparable with
    the benign control set, which is extracted from raw executables with
    pefile (also the file's own import table).
    """
    cape_imports = (report.get("target", {}) or {}).get("file", {}).get("pe", {}).get("imports")
    if cape_imports:
        return _flatten_import_container(cape_imports)

    legacy_imports = (report.get("static", {}) or {}).get("pe_imports")
    if legacy_imports:
        return _flatten_import_container(legacy_imports)

    return []


def get_unpacked_imports(report):
    """
    Imports visible only AFTER the sample unpacked itself.

    A packed dropper's own import table understates what the malware can do:
    WannaCry's submitted file declares only CryptReleaseContext, while the
    payload CAPE extracted at runtime also imports CryptGenRandom. CAPE
    surfaces these through CAPE.payloads and dropped files, which pure
    static analysis of the original binary cannot see.

    Returned separately from get_imports() rather than merged into it,
    because the benign control set has no equivalent (benign programs are
    not unpacked at runtime), so mixing them would break comparability.
    """
    names = []
    payloads = (report.get("CAPE", {}) or {}).get("payloads", []) or []
    for payload in payloads:
        if isinstance(payload, dict):
            names.extend(_flatten_import_container(
                payload.get("pe", {}).get("imports")))
    for dropped in report.get("dropped", []) or []:
        if isinstance(dropped, dict):
            names.extend(_flatten_import_container(
                dropped.get("pe", {}).get("imports")))
    return names


def get_strings(report):
    """
    Extracted strings, used for crypto-library fingerprinting.
    CAPE nests them under target.file.strings; legacy Cuckoo put them at the
    top level.
    """
    cape_strings = (report.get("target", {}) or {}).get("file", {}).get("strings")
    if isinstance(cape_strings, list) and cape_strings:
        return [x for x in cape_strings if isinstance(x, str)]

    legacy_strings = report.get("strings")
    if isinstance(legacy_strings, list):
        return [x for x in legacy_strings if isinstance(x, str)]

    return []


def categorize_imports(import_names):
    lowered = {n.lower() for n in import_names}
    hits = {}
    for category, keywords in IMPORT_CATEGORIES.items():
        found = set()
        for kw in keywords:
            kw_l = kw.lower()
            if any(kw_l in name for name in lowered):
                found.add(kw)
        hits[category] = len(found)
    return hits


def detect_crypto_libs(strings):
    joined = "\n".join(strings).lower()
    return {lib for lib, fps in CRYPTO_LIB_FINGERPRINTS.items()
            if any(fp.lower() in joined for fp in fps)}


def extract_static_features(report):
    import_names = get_imports(report)
    category_hits = categorize_imports(import_names)
    crypto_libs = detect_crypto_libs(get_strings(report))
    indicative = [c for c in INDICATIVE_CATEGORIES if category_hits.get(c, 0) > 0]

    features = {"total_imports": len(import_names)}
    for category in IMPORT_CATEGORIES:
        features[f"imp_{category}"] = category_hits.get(category, 0)
    features["indicative_category_count"] = len(indicative)
    features["static_crypto_libs"] = ";".join(sorted(crypto_libs)) if crypto_libs else ""

    # Unpacked view: what became visible only after the sample ran and
    # unpacked itself. Reported separately (see get_unpacked_imports).
    unpacked_names = get_unpacked_imports(report)
    if unpacked_names:
        unpacked_hits = categorize_imports(unpacked_names)
        unpacked_indicative = [c for c in INDICATIVE_CATEGORIES
                               if unpacked_hits.get(c, 0) > 0]
        features["unpacked_total_imports"] = len(unpacked_names)
        features["unpacked_indicative_category_count"] = len(unpacked_indicative)
        # Categories the packed original hid from static analysis.
        features["categories_revealed_by_unpacking"] = max(
            0, len(unpacked_indicative) - len(indicative))
    else:
        features["unpacked_total_imports"] = 0
        features["unpacked_indicative_category_count"] = ""
        features["categories_revealed_by_unpacking"] = ""

    return features


# ---------------- Static <-> dynamic interaction ----------------

def compute_interaction_features(static_features, dynamic_features):
    """
    Relationships between what the binary was built to do (imports) and what
    it actually did at runtime. Only meaningful when both views exist.

    - crypto_imported_not_called: the binary imports Windows crypto APIs but
      made no crypto call at runtime. Indicates either a trigger failure or
      that encryption was done through a statically-linked / custom
      implementation instead.
    - crypto_called_not_imported: crypto calls observed without matching
      imports, which suggests runtime API resolution (GetProcAddress) --
      a known evasion technique.
    - static_dynamic_agreement: both views agree that crypto is in play.
    """
    imported_crypto = static_features.get("imp_crypto", 0) > 0
    called_crypto = dynamic_features.get("n_crypto_calls", 0) > 0
    has_static = static_features.get("total_imports", 0) > 0

    if not has_static:
        # No import table (packed / unreadable): interaction is undefined.
        return {
            "crypto_imported_not_called": "",
            "crypto_called_not_imported": "",
            "static_dynamic_agreement": "",
        }

    return {
        "crypto_imported_not_called": int(imported_crypto and not called_crypto),
        "crypto_called_not_imported": int(called_crypto and not imported_crypto),
        "static_dynamic_agreement": int(imported_crypto == called_crypto),
    }


# ---------------- Feature row assembly ----------------

# `verdict` records what the run actually did, which `label` and `coverage`
# no longer capture between them. Every sample here is labelled ransomware,
# and coverage now says only whether the sandbox saw it run -- so without
# this column a sample that encrypted 140 decoy files and one that installed
# persistence and quietly gave up are indistinguishable in the feature table.
#
# The distinction is the point of several questions the data should answer:
# what separates the runs that reached encryption from those that stopped
# short, and whether preparation behaviour means anything on its own.
IDENTITY_FIELDS = ["sample_id", "sha256", "label", "verdict", "family", "source",
                    "coverage", "static_readable", "malscore", "cape_family"]
DYNAMIC_FIELDS = [
    "n_file_writes", "n_crypto_calls", "write_crypto_pearson",
    "crypto_buffer_entropy_mean", "crypto_buffer_entropy_max",
    "n_read", "n_write", "n_delete", "n_move", "n_copy", "n_execute",
    "delete_to_write_ratio", "move_to_write_ratio",
    "destructive_extension_variety",
    "active_windows", "destructive_chain_windows",
    "write_only_nondestructive_windows", "other_windows",
]
STATIC_FIELDS = (["total_imports"] + [f"imp_{c}" for c in IMPORT_CATEGORIES] +
                  ["indicative_category_count", "static_crypto_libs",
                   "unpacked_total_imports", "unpacked_indicative_category_count",
                   "categories_revealed_by_unpacking"])
INTERACTION_FIELDS = ["crypto_imported_not_called", "crypto_called_not_imported",
                       "static_dynamic_agreement"]
PREPARATION_FIELDS = (["n_executed_commands"] +
                       [f"n_{k}" for k in COMMAND_PATTERNS] +
                       ["n_services_created", "n_services_started",
                        "n_service_events", "n_registry_writes",
                        "n_registry_deletes", "prep_to_destroy_delay_sec",
                        "n_prep_processes", "n_prep_categories",
                        "n_prep_before_destroy", "prep_precedes_destroy",
                        "prep_to_first_destroy_sec", "n_destroy_after_prep",
                        "destroy_span_after_prep_sec", "n_prep_during_destroy",
                        "prep_overlaps_destroy", "prep_position_in_destroy"])

FEATURE_FIELDNAMES = (IDENTITY_FIELDS + DYNAMIC_FIELDS + STATIC_FIELDS +
                       INTERACTION_FIELDS + PREPARATION_FIELDS)


def get_cape_metadata(report):
    """
    Metadata CAPE produces that no other source gives us:
      - malscore: CAPE's own aggregate maliciousness score
      - cape_family: the family CAPE's signatures attributed the sample to,
        which is independent of the family label we recorded at download
        time. Disagreement between the two is worth knowing about.
    """
    malscore = report.get("malscore", "")
    cape_family = ""
    detections = report.get("detections", [])
    if isinstance(detections, list) and detections:
        first = detections[0]
        if isinstance(first, dict):
            cape_family = first.get("family", "")
    return {
        "malscore": malscore if malscore is not None else "",
        "cape_family": cape_family,
    }


# API calls below which a sample is taken not to have executed.
#
# This used to match the 500 in analyze_result, on the reasoning that the two
# should agree on what "it ran" means. They should not, because they are
# deciding different things. analyze_result asks whether there was enough
# activity to judge a verdict from; this asks whether the dynamic features
# are observations or absences, and a program that made two hundred calls has
# been observed.
#
# Matching them cost something measurable. Three of the sixty-eight hard
# negatives fell below 500 and were written out as static-only, which left
# their behavioural features empty. A row of empty features is
# indistinguishable from a program that never ran, the model does not flag
# it, and it counts as a correct negative -- so the false positive rate on
# that set was reported lower than it was, in the direction that flatters
# the detector.
#
# A hundred is where a process has started and done something. Below that
# there is genuinely nothing to measure. The relational extraction already
# works this way, deciding per feature whether it has enough events rather
# than discarding the whole run, and this brings the two into line.
MIN_TOTAL_CALLS_FOR_DYNAMIC = 100


def report_shows_execution(report):
    """
    Whether the sandbox recorded the sample actually running.

    This, and not the verdict, decides whether the dynamic features are real
    observations. An earlier version gave dynamic features only to runs
    judged TRUE_ENCRYPTION, which discarded every sample that executed and
    did not encrypt -- 82 of them in one batch, including a Zeppelin run that
    spent 669 seconds installing persistence, enumerating drives, probing a
    network share and deleting its own traces across 10,732 API calls.

    Those runs are the clearest evidence available of what ransomware does
    before it starts encrypting, and they are precisely the ones a detector
    would need to act on in time. Writing them out as static-only threw that
    away.

    The original reasoning still holds for samples that never ran: their
    n_delete of 0 means "not observed", not "observed to be zero". But a
    sample that made ten thousand calls and destroyed nothing has been
    observed to destroy nothing, and that is a fact worth recording.
    """
    total = 0
    for process in report.get("behavior", {}).get("processes", []) or []:
        total += len(process.get("calls", []) or [])
    return total >= MIN_TOTAL_CALLS_FOR_DYNAMIC


def build_feature_row(report, sample_id, label, family, source, window_sec,
                       dynamic_ok=True, verdict=""):
    """
    Assemble one feature row.

    dynamic_ok=False produces a static-only row: the dynamic and interaction
    columns are left blank rather than filled with zeros. This distinction
    matters. A sample that never executed has no delete count -- writing 0
    would tell the model "this ransomware deletes nothing", which is false.
    Blank means "not observed"; 0 means "observed to be zero".
    """
    static = extract_static_features(report)
    cape_meta = get_cape_metadata(report)
    sha256 = (report.get("target", {}) or {}).get("file", {}).get("sha256", "")

    row = {
        "sample_id": sample_id,
        "sha256": sha256,
        "label": label,
        "verdict": verdict,
        "family": family or "",
        "source": source,
        "coverage": "full" if dynamic_ok else "static_only",
        "static_readable": int(static.get("total_imports", 0) >= MIN_READABLE_IMPORTS),
    }
    row.update(cape_meta)

    if dynamic_ok:
        dynamic = extract_dynamic_features(report, window_sec)
        row.update(dynamic)
        row.update(compute_interaction_features(static, dynamic))
        row.update(extract_preparation_features(
            report, extract_lifecycle_events(report)))
    else:
        for field in DYNAMIC_FIELDS + INTERACTION_FIELDS + PREPARATION_FIELDS:
            row[field] = ""

    row.update(static)
    return row


def load_existing_features(features_out):
    """
    Read back what is already in the feature table so re-running the
    pipeline does not append the same analysis twice.

    Returns (sample_ids, sha256_to_sample_id).

    Two kinds of duplication matter and they are not the same thing:
      - Same sample_id: the same CAPE analysis processed twice. Always a
        mistake; skipped silently.
      - Same sha256 under a different sample_id: the same binary analysed
        more than once (e.g. re-submitted with a longer timeout). That may
        be deliberate, but leaving both rows in risks the same sample
        landing in both the training and test split later, so it is
        flagged rather than silently accepted.
    """
    if not features_out or not os.path.exists(features_out):
        return set(), {}
    sample_ids = set()
    sha_to_id = {}
    try:
        with open(features_out, newline="") as f:
            for row in csv.DictReader(f):
                sid = str(row.get("sample_id", "")).strip()
                sha = str(row.get("sha256", "")).strip()
                if sid:
                    sample_ids.add(sid)
                if sha:
                    sha_to_id.setdefault(sha, sid)
    except OSError:
        return set(), {}
    return sample_ids, sha_to_id


def append_feature_row(features_out, row):
    file_exists = os.path.exists(features_out)
    with open(features_out, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in FEATURE_FIELDNAMES})


def rewrite_feature_row(features_out, row):
    """Replace an existing row with the same sample_id (used by --overwrite)."""
    rows = []
    with open(features_out, newline="") as f:
        rows = list(csv.DictReader(f))
    replaced = False
    for i, existing in enumerate(rows):
        if str(existing.get("sample_id", "")).strip() == str(row["sample_id"]):
            rows[i] = {k: row.get(k, "") for k in FEATURE_FIELDNAMES}
            replaced = True
            break
    if not replaced:
        rows.append({k: row.get(k, "") for k in FEATURE_FIELDNAMES})
    with open(features_out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in FEATURE_FIELDNAMES})


# ---------------- Manifest lookup (for family metadata) ----------------

def load_manifest_by_sha(manifest_path):
    if not manifest_path or not os.path.exists(manifest_path):
        return {}
    entries = {}
    with open(manifest_path, newline="") as f:
        for row in csv.DictReader(f):
            entries[row["sha256"]] = row
    return entries


# ---------------- Report loading ----------------

def resolve_report_path(path):
    p = Path(path)
    if p.is_dir():
        candidate = p / "reports" / "report.json"
        return candidate if candidate.exists() else None
    return p if p.is_file() else None


def open_report(path):
    """
    Load a report from whichever shape it is in.

    Three are in circulation. A live analysis directory holds
    reports/report.json. The cleanup stage keeps only a gzip archive named
    task_<id>_report.json.gz. And a report may be handed over as a plain
    file.

    Reading all three matters more than it sounds. The archives exist so that
    features can be recomputed when their definitions change, which has
    happened repeatedly -- but until now only live directories could actually
    be re-read, so the archives were unusable for the purpose they were kept
    for.

    Returns (report, sample_id) where sample_id is taken from the path when
    the report itself does not carry an analysis id.
    """
    path = Path(path)

    if path.is_dir():
        candidate = path / "reports" / "report.json"
        if not candidate.exists():
            return None, None
        with open(candidate, "r", errors="replace") as f:
            return json.load(f), path.name

    if not path.exists():
        return None, None

    # task_137_report.json.gz -> 137
    match = re.search(r"task[_-]?(\d+)", path.name)
    fallback_id = match.group(1) if match else path.stem

    if path.suffix == ".gz":
        with gzip.open(path, "rt", errors="replace") as f:
            return json.load(f), fallback_id

    with open(path, "r", errors="replace") as f:
        return json.load(f), fallback_id


def _extract_for_pool(target, label, source, window_sec, manifest_by_sha, id_prefix):
    """
    Worker entry point: build one row and hand it back, writing nothing.

    Defined at module level so the pool can pickle it, and given
    features_out=None so that only the parent touches the CSV.
    """
    path, verdict = target
    try:
        return process_one(path, label, source, window_sec, None, manifest_by_sha,
                            quiet=True, dynamic_ok=None, verdict=verdict,
                            id_prefix=id_prefix)
    except Exception as e:
        print(f"\n   [!] {path}: {type(e).__name__}: {e}")
        return None


def process_one(path, label, source, window_sec, features_out, manifest_by_sha,
                 quiet=False, sample_id_override=None, id_prefix="",
                 existing_ids=None, existing_shas=None, overwrite=False,
                 dynamic_ok=None, verdict=""):
    try:
        report, path_id = open_report(path)
    except (json.JSONDecodeError, OSError) as e:
        if not quiet:
            print(f"[!] {path}: {e}")
        return None
    if report is None:
        if not quiet:
            print(f"[!] no readable report at {path}")
        return None

    info = report.get("info", {}) or {}
    sample_id = sample_id_override or str(info.get("id") or path_id or "")
    if id_prefix and not sample_id_override:
        # Task ids restart from 1 on every host, so two machines analysing in
        # parallel will both produce a task 500. Without a prefix the second
        # one is silently dropped as a duplicate sample_id and its features
        # are lost without any warning.
        sample_id = f"{id_prefix}{sample_id}"
    sha256 = (report.get("target", {}) or {}).get("file", {}).get("sha256", "")

    # Enrich with family from the manifest when available.
    family = ""
    if sha256 and sha256 in manifest_by_sha:
        family = manifest_by_sha[sha256].get("family", "")

    # Skip analyses already present, so the pipeline can be re-run safely.
    if existing_ids is not None and sample_id in existing_ids and not overwrite:
        if not quiet:
            print(f"{sample_id:<8} (already in feature table -- skipped; "
                  f"use --overwrite to replace)")
        return None

    if dynamic_ok is None:
        dynamic_ok = report_shows_execution(report)

    row = build_feature_row(report, sample_id, label, family, source, window_sec,
                            dynamic_ok=dynamic_ok, verdict=verdict)

    # Same binary, different analysis: allowed, but flagged because leaving
    # both rows in can put the same sample in both train and test splits.
    if existing_shas and sha256 and sha256 in existing_shas:
        prior = existing_shas[sha256]
        if prior != sample_id and not quiet:
            print(f"   [warn] sha256 of task {sample_id} already present as task "
                  f"{prior}; same binary analysed twice -- deduplicate before modelling")

    if features_out:
        if overwrite and existing_ids is not None and sample_id in existing_ids:
            rewrite_feature_row(features_out, row)
        else:
            append_feature_row(features_out, row)
        if existing_ids is not None:
            existing_ids.add(sample_id)
        if existing_shas is not None and sha256:
            existing_shas.setdefault(sha256, sample_id)

    if not quiet:
        readable = "" if row["static_readable"] else "  [packed: static unusable]"
        if dynamic_ok:
            print(f"{sample_id:<8} {family[:12]:<13} full        "
                  f"read={row['n_read']:<5} write={row['n_write']:<5} "
                  f"del={row['n_delete']:<5} crypto={row['n_crypto_calls']:<5} "
                  f"imports={row['total_imports']:<5} ind={row['indicative_category_count']}/5{readable}")
        else:
            print(f"{sample_id:<8} {family[:12]:<13} static_only "
                  f"{'(no dynamic data)':<40} "
                  f"imports={row['total_imports']:<5} ind={row['indicative_category_count']}/5{readable}")
    return row


def main():
    parser = argparse.ArgumentParser(
        description="Extract combined dynamic + static features from CAPE analyses.")
    parser.add_argument("path", nargs="?", help="An analysis directory or report.json")
    parser.add_argument("--batch", metavar="ANALYSES_DIR",
                         help="Process analyses under this directory")
    parser.add_argument("--results", metavar="CSV",
                         help="analyze_result.py output; restricts batch to matching verdicts")
    parser.add_argument("--keep-verdict", default="TRUE_ENCRYPTION",
                         help="With --results, which verdict to process (default: TRUE_ENCRYPTION)")
    parser.add_argument("--features-out", default=None, help="Feature table CSV to append to")
    parser.add_argument("--label", default="ransomware", help="Label for these samples")
    parser.add_argument("--source", default="cape", help="Data source tag (default: cape)")
    parser.add_argument("--manifest", default=None,
                         help="Manifest CSV, used to enrich rows with family metadata")
    parser.add_argument("--window", type=float, default=1.0,
                         help="Time window in seconds for correlation features (default: 1.0)")
    parser.add_argument("--sample-id", default=None,
                         help="Override the sample id (defaults to the CAPE task id)")
    parser.add_argument("--static-for-all", action="store_true",
                         help="Process every analysis, not only those reaching "
                              "--keep-verdict. Static features are valid regardless of "
                              "execution, and dynamic features are emitted for anything "
                              "the sandbox actually saw run -- including samples that "
                              "executed without encrypting, which is where preparation "
                              "behaviour is visible.")
    parser.add_argument("--workers", type=int, default=1, metavar="N",
                         help="Parse this many reports at once in batch mode. Rows are "
                              "still written by the parent process alone. On a machine "
                              "also running the sandbox, leave this at 1 or 2.")
    parser.add_argument("--id-prefix", default="",
                         help="Prepend this to every sample id. Needed when merging "
                              "results from two hosts, whose task numbering overlaps: "
                              "without it the second host's rows are dropped as "
                              "duplicates. For example --id-prefix B gives B500.")
    parser.add_argument("--verdict", default="",
                         help="Verdict to record for a single analysis. In batch mode it "
                              "is taken from --results instead.")
    parser.add_argument("--overwrite", action="store_true",
                         help="Recompute and replace rows already in the feature table "
                              "(default: skip them, so re-runs are safe)")
    args = parser.parse_args()

    manifest_by_sha = load_manifest_by_sha(args.manifest)
    existing_ids, existing_shas = load_existing_features(args.features_out)
    if existing_ids:
        print(f"Feature table already contains {len(existing_ids)} samples; "
              f"{'recomputing' if args.overwrite else 'these will be skipped'}\n")

    if args.batch:
        base = Path(args.batch)
        if not base.is_dir():
            print(f"[!] not a directory: {args.batch}")
            sys.exit(1)

        # Map each analysis to its verdict so we can decide, per sample,
        # whether dynamic features are meaningful.
        verdict_by_id = {}
        if args.results:
            with open(args.results, newline="") as f:
                for r in csv.DictReader(f):
                    verdict_by_id[str(r.get("task_id", "")).strip()] = r.get("verdict", "")
            n_pass = sum(1 for v in verdict_by_id.values() if v == args.keep_verdict)
            if args.static_for_all:
                print(f"Processing every analysis. {n_pass} reached "
                      f"{args.keep_verdict}; coverage is set per analysis from "
                      f"whether the sample executed, not from its verdict.\n")
            else:
                print(f"Restricting to {n_pass} analyses with verdict "
                      f"{args.keep_verdict}\n")

        # Numerically named directories only; see the note in analyze_result.
        subdirs = sorted((d for d in base.iterdir() if d.is_dir() and d.name.isdigit()),
                          key=lambda d: int(d.name))
        if not subdirs:
            # A directory of archives rather than of analysis directories.
            # Sorted by the task number inside the name, not by the name
            # itself: "task_100" sorts before "task_1000" as text, which
            # scatters the output rows into an order that looks arbitrary.
            archives = sorted(
                (p for p in base.iterdir()
                 if p.is_file() and (p.suffix == ".gz" or p.name.endswith(".json"))),
                key=lambda p: (int(m.group(1))
                               if (m := re.search(r"task[_-]?(\d+)", p.name))
                               else 10**9, p.name))
            if archives:
                print(f"No analysis directories here; reading {len(archives)} "
                      f"archived reports instead\n")
                subdirs = archives

        print(f"{'task':<8} {'family':<13} {'coverage':<11} {'features'}")
        print("-" * 100)

        def task_id_of(path):
            """
            The task number for a batch entry.

            An analysis directory is named after its task, so its name is the
            id. An archive is named task_1234_report.json.gz, and looking the
            whole filename up in the verdict table silently finds nothing --
            which left the verdict column empty for every row extracted from
            archives, and with it the only way to tell an encrypting run from
            one that merely executed.
            """
            if path.is_dir():
                return path.name
            m = re.search(r"task[_-]?(\d+)", path.name)
            return m.group(1) if m else path.stem

        n_full = n_static = 0

        # Work out what to process before doing any of it, so the list can be
        # handed to a pool.
        targets = []
        for d in subdirs:
            task_id = task_id_of(d)
            verdict = verdict_by_id.get(task_id) if verdict_by_id else args.keep_verdict
            if verdict != args.keep_verdict and not args.static_for_all:
                continue
            targets.append((str(d), verdict or ""))

        def record(row):
            nonlocal n_full, n_static
            if not row:
                return
            if row["coverage"] == "full":
                n_full += 1
            else:
                n_static += 1

        if args.workers > 1 and len(targets) > 1:
            # Parsing dominates the runtime and each report is independent,
            # so the work is spread across processes. Only the parent writes
            # the CSV: concurrent appends from several processes would
            # interleave and corrupt rows.
            from concurrent.futures import ProcessPoolExecutor
            from functools import partial
            work = partial(_extract_for_pool,
                           label=args.label, source=args.source,
                           window_sec=args.window, manifest_by_sha=manifest_by_sha,
                           id_prefix=args.id_prefix)
            print(f"Parsing {len(targets)} reports across {args.workers} processes\n")
            with ProcessPoolExecutor(max_workers=args.workers) as pool:
                done = 0
                for row in pool.map(work, targets, chunksize=4):
                    done += 1
                    if done % 50 == 0 or done == len(targets):
                        print(f"\r   {done}/{len(targets)}", end="", flush=True)
                    if not row:
                        continue
                    sid, sha = row["sample_id"], row["sha256"]
                    if existing_shas and sha and sha in existing_shas \
                            and existing_shas[sha] != sid:
                        print(f"\n   [warn] sha256 of task {sid} already present as "
                              f"task {existing_shas[sha]}; same binary analysed twice "
                              f"-- deduplicate before modelling")
                    if args.features_out:
                        if args.overwrite and existing_ids is not None \
                                and sid in existing_ids:
                            rewrite_feature_row(args.features_out, row)
                        else:
                            append_feature_row(args.features_out, row)
                        if existing_ids is not None:
                            existing_ids.add(sid)
                        if existing_shas is not None and sha:
                            existing_shas.setdefault(sha, sid)
                    record(row)
            print()
        else:
            for path, verdict in targets:
                row = process_one(path, args.label, args.source, args.window,
                                  args.features_out, manifest_by_sha,
                                  existing_ids=existing_ids, existing_shas=existing_shas,
                                  overwrite=args.overwrite, dynamic_ok=None,
                                  verdict=verdict, id_prefix=args.id_prefix)
                record(row)

        processed = n_full + n_static
        print(f"\n[done] {processed} rows written: {n_full} full, {n_static} static-only")
        if verdict_by_id:
            enc = sum(1 for d in subdirs
                      if verdict_by_id.get(task_id_of(d)) == args.keep_verdict)
            print(f"        of the full rows, those that reached {args.keep_verdict} "
                  f"vs ran without it is recorded in the verdict column")
        if args.features_out:
            print(f"[saved] {args.features_out}")

    elif args.path:
        row = process_one(args.path, args.label, args.source, args.window,
                          args.features_out, manifest_by_sha,
                          sample_id_override=args.sample_id,
                          existing_ids=existing_ids, existing_shas=existing_shas,
                          overwrite=args.overwrite, verdict=args.verdict,
                          id_prefix=args.id_prefix)
        if row and args.features_out:
            print(f"[saved] feature row -> {args.features_out}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
