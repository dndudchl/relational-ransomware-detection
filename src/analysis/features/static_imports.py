#!/usr/bin/env python3
"""
static_imports.py - Extract ransomware-indicative static features
(PE imports + crypto-library string fingerprints) from either:
  - a sandbox report.json (static.pe_imports), for the ransomware dataset, or
  - a raw PE file (.exe/.dll) via pefile, for a benign control set.

Both input paths produce the SAME feature columns, so ransomware samples
(from report.json) and benign samples (from exe) can be compared directly
using identical feature definitions.

Motivation
----------
Dynamic (behavioral) analysis only yields data when a sample actually
executes its payload; most modern samples fail to trigger. The sandbox's
STATIC section (static.pe_imports, strings) is available even for samples
that never ran, because it comes from the binary. Inspecting a real
AvosLocker sample showed the static section is rich: it imports
CryptEncrypt/CryptGenRandom (crypto), WNet* (network-share spread),
RmStartSession (Restart Manager -- unlock in-use files to encrypt them),
Toolhelp32/Process32Next (process enumeration), FindFirstVolumeW (whole
-disk sweep), and its strings revealed a statically-linked Crypto++ 8.5.

The single presence of any one import (e.g. CryptEncrypt) is NOT a
ransomware signal on its own -- benign backup/compression tools import it
too. The signal is the CO-OCCURRENCE across categories, which is why we
count categories and expose indicative_category_count. That is also why a
benign control set is essential: without it we cannot know whether these
imports actually separate ransomware from goodware.

Usage
-----
  # ransomware dataset (sandbox reports)
  python3 static_imports.py <report.json>
  python3 static_imports.py --batch <dir_of_reports> --out static_features.csv

  # benign control set (raw executables)
  python3 static_imports.py --pe <program.exe>
  python3 static_imports.py --pe-batch <dir_of_exes> --label benign --out benign_static_features.csv

The --label option (default: derived) lets you tag rows; useful to mark
the benign set so the two CSVs can be concatenated for modeling.
"""

import sys
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

# Import name -> category. Case-insensitive substring match on the import
# name, so "Crypt" catches CryptEncrypt, CryptGenRandom, etc. Categories
# reflect distinct ransomware behaviors so CO-OCCURRENCE can be measured.
IMPORT_CATEGORIES = {
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
        "CryptExportKey", "CryptAcquireContext", "CryptDestroyKey",
        "CryptReleaseContext", "CryptGenRandom", "BCryptEncrypt",
        "BCryptGenRandom", "CryptStringToBinary", "CryptImportPublicKeyInfo",
    ],
    "random": [
        "CryptGenRandom", "BCryptGenRandom", "RtlGenRandom", "rand_s",
    ],
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
        "WNetOpenEnum", "WNetAddConnection", "WNetEnumResource",
        "WNetCloseEnum",
    ],
    "file_unlock": [  # Restart Manager: unlock in-use files to encrypt them
        "RmStartSession", "RmRegisterResources", "RmGetList", "RmEndSession",
    ],
    "process_enum": [  # enumerate/kill AV, databases, backup services
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "OpenProcessToken", "AdjustTokenPrivileges",
    ],
    "shadow_service": [  # delete shadow copies / stop services (best-effort)
        "DeleteFileW", "ControlService", "OpenSCManager", "OpenServiceW",
    ],
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


# ---------------- Import extraction: two sources, same output ----------------

def get_imports_from_report(report):
    """Extract imported function names from a sandbox report.json's
    static.pe_imports = [ {dll, imports:[{name}]} ]."""
    names = []
    static = report.get("static", {}) or {}
    pe_imports = static.get("pe_imports", []) or []
    for dll_entry in pe_imports:
        for imp in dll_entry.get("imports", []) or []:
            name = imp.get("name")
            if name:
                names.append(name)
    return names


def get_strings_from_report(report):
    s = report.get("strings", [])
    if isinstance(s, list):
        return [x for x in s if isinstance(x, str)]
    return []


def get_imports_from_pe(pe_path):
    """Extract imported function names directly from a raw PE file using
    pefile. Returns (import_names, error_or_None)."""
    try:
        import pefile
    except ImportError:
        return None, "pefile not installed (pip install pefile)"
    try:
        pe = pefile.PE(pe_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    except Exception as e:  # pefile raises various exceptions on malformed/non-PE
        return None, f"PE parse error: {e}"

    names = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    try:
                        names.append(imp.name.decode("utf-8", "ignore"))
                    except AttributeError:
                        names.append(str(imp.name))
    pe.close()
    return names, None


def get_strings_from_pe(pe_path):
    """Cheap printable-ASCII string scan of a raw file, for crypto-lib
    fingerprinting. Not a full 'strings' implementation but sufficient to
    catch library markers like 'cryptopp' or 'OpenSSL'."""
    strings = []
    try:
        with open(pe_path, "rb") as f:
            data = f.read()
    except OSError:
        return strings
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= 5:
                strings.append(current.decode("ascii", "ignore"))
            current = bytearray()
    if len(current) >= 5:
        strings.append(current.decode("ascii", "ignore"))
    return strings


# ---------------- Feature computation (shared by both sources) ----------------

def categorize_imports(import_names):
    """Count, per category, how many DISTINCT indicative imports are present."""
    lowered = {n.lower() for n in import_names}
    category_hits = {}
    for category, keywords in IMPORT_CATEGORIES.items():
        hits = set()
        for kw in keywords:
            kw_l = kw.lower()
            for name in lowered:
                if kw_l in name:
                    hits.add(kw)
                    break
        category_hits[category] = len(hits)
    return category_hits


def detect_crypto_libs(strings):
    found = set()
    joined_lower = "\n".join(strings).lower()
    for lib, fps in CRYPTO_LIB_FINGERPRINTS.items():
        if any(fp.lower() in joined_lower for fp in fps):
            found.add(lib)
    return found


def build_row(name, label, import_names, strings):
    category_hits = categorize_imports(import_names)
    crypto_libs = detect_crypto_libs(strings)
    indicative = [c for c in INDICATIVE_CATEGORIES if category_hits.get(c, 0) > 0]

    row = {"file": name, "label": label, "total_imports": len(import_names)}
    for category in IMPORT_CATEGORIES:
        row[f"imp_{category}"] = category_hits.get(category, 0)
    row["indicative_category_count"] = len(indicative)
    row["static_crypto_libs"] = ";".join(sorted(crypto_libs)) if crypto_libs else ""
    return row


FIELDNAMES = (["file", "label", "total_imports"] +
              [f"imp_{c}" for c in IMPORT_CATEGORIES] +
              ["indicative_category_count", "static_crypto_libs"])


# ---------------- Per-input analyzers ----------------

def analyze_report(report_path, label):
    try:
        with open(report_path, "r", errors="replace") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {"file": Path(report_path).name, "error": str(e)}
    names = get_imports_from_report(report)
    strings = get_strings_from_report(report)
    return build_row(Path(report_path).name, label, names, strings)


def analyze_pe(pe_path, label):
    names, err = get_imports_from_pe(pe_path)
    if err:
        return {"file": Path(pe_path).name, "error": err}
    strings = get_strings_from_pe(pe_path)
    return build_row(Path(pe_path).name, label, names, strings)


# ---------------- Output ----------------

def print_single(row):
    if "error" in row:
        print(f"[!] {row['file']}: {row['error']}")
        return
    print("=" * 60)
    print(f"File: {row['file']}  (label: {row['label']})")
    print("=" * 60)
    print(f"Total imports: {row['total_imports']}")
    print(f"\n[Import categories] (distinct indicative imports per category)")
    for category in IMPORT_CATEGORIES:
        count = row[f"imp_{category}"]
        marker = " <--" if count > 0 and category in INDICATIVE_CATEGORIES else ""
        print(f"   {category:<16} {count}{marker}")
    print(f"\n[Ransomware-indicative categories present]: "
          f"{row['indicative_category_count']} / {len(INDICATIVE_CATEGORIES)}")
    print(f"[Statically-linked crypto libs in strings]: "
          f"{row['static_crypto_libs'] or '(none detected)'}")


def write_batch(rows, out_csv):
    good = [r for r in rows if "error" not in r]
    errs = [r for r in rows if "error" in r]

    header = (f"{'file':<52} {'label':<10} {'imp':>5} {'cryp':>4} {'vol':>4} "
              f"{'net':>4} {'unlk':>4} {'proc':>4} {'ind':>4} {'libs':<14}")
    print(header)
    print("-" * len(header))
    for r in good:
        fname = r["file"] if len(r["file"]) <= 50 else r["file"][:47] + "..."
        print(f"{fname:<52} {r['label']:<10} {r['total_imports']:>5} "
              f"{r['imp_crypto']:>4} {r['imp_volume_enum']:>4} {r['imp_network_spread']:>4} "
              f"{r['imp_file_unlock']:>4} {r['imp_process_enum']:>4} "
              f"{r['indicative_category_count']:>4} {r['static_crypto_libs']:<14}")

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in good:
            writer.writerow({k: r.get(k, "") for k in FIELDNAMES})
    print(f"\n[saved] {len(good)} rows -> {out_csv}")
    if errs:
        print(f"[note] {len(errs)} inputs could not be parsed (packed / non-PE / malformed):")
        for r in errs[:10]:
            print(f"   {r['file']}: {r['error']}")
        if len(errs) > 10:
            print(f"   ... and {len(errs) - 10} more")


# ---------------- Main ----------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract static PE-import ransomware features from reports or exes.")
    parser.add_argument("report_path", nargs="?", help="Single sandbox report.json")
    parser.add_argument("--batch", metavar="DIR", help="Directory of report.json files")
    parser.add_argument("--pe", metavar="EXE", help="Single raw PE file (.exe/.dll)")
    parser.add_argument("--pe-batch", metavar="DIR", help="Directory of raw PE files")
    parser.add_argument("--label", default=None,
                         help="Label to tag rows (default: 'ransomware' for reports, "
                              "'benign' for PE inputs)")
    parser.add_argument("--out", default="static_features.csv", help="CSV output (batch modes)")
    parser.add_argument("--pe-glob", default="*.exe",
                         help="Glob for --pe-batch (default: *.exe; use '*' for all files)")
    args = parser.parse_args()

    if args.batch:
        label = args.label or "ransomware"
        reports = sorted(Path(args.batch).glob("*.json"))
        rows = [analyze_report(p, label) for p in reports]
        write_batch(rows, args.out)

    elif args.pe_batch:
        label = args.label or "benign"
        pes = sorted(Path(args.pe_batch).glob(args.pe_glob))
        if not pes:
            print(f"[!] No files matching {args.pe_glob} in {args.pe_batch}")
            sys.exit(1)
        rows = [analyze_pe(p, label) for p in pes]
        write_batch(rows, args.out)

    elif args.pe:
        label = args.label or "benign"
        print_single(analyze_pe(args.pe, label))

    elif args.report_path:
        label = args.label or "ransomware"
        print_single(analyze_report(args.report_path, label))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()