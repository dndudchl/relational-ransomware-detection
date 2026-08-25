#!/usr/bin/env python3
"""
analyze_result.py - Decide whether a CAPE analysis is usable, in one step.

This merges what used to be two separate tools:
  1. triage.py            -- did the sample execute at all?
  2. verify_encryption.py -- did it actually attack the planted decoy files?

They were always run in this fixed order, so they are merged here into a
single staged verdict. The staging is preserved internally: if a sample
never really executed, there is no point inspecting victim files, so the
second stage is skipped and the sample is reported as FAILED.

Verdicts
--------
  FAILED               - too little activity; the sample did not run
                         meaningfully (evasion, crash, missing args)
  NO_VICTIM_ACTIVITY   - it ran, but never touched the planted decoy files
                         (e.g. only unpacked itself into %TEMP%)
  WEAK_VICTIM_ACTIVITY - some decoy-file damage, but below threshold;
                         worth a manual look
  TRUE_ENCRYPTION      - genuinely attacked the planted decoy files;
                         this is the only verdict that proceeds to feature
                         extraction

Manifest integration
--------------------
If --manifest is given and the analysis can be matched to a sample (via
the sha256 recorded by CAPE, or via --sha256), the verdict is written back
to the manifest automatically. No manual bookkeeping is needed.

Usage
-----
  # Single analysis directory or report
  python3 analyze_result.py /opt/CAPEv2/storage/analyses/61
  python3 analyze_result.py /opt/CAPEv2/storage/analyses/61/reports/report.json

  # Every analysis under the CAPE storage directory, writing a summary CSV
  python3 analyze_result.py --batch /opt/CAPEv2/storage/analyses \\
      --out analysis_results.csv --manifest ../../data/manifests/manifest_all.csv

  # Only print the sample ids that passed, for scripting
  python3 analyze_result.py --batch /opt/CAPEv2/storage/analyses --list-passed
"""

import os
import sys
import re
import gzip
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

# ---------------- Stage 1 config: did it execute? ----------------

# Below this many total API calls, the sample effectively did not run.
MIN_TOTAL_CALLS = 500
# Below this many destructive file events anywhere, execution is doubtful.
# Retained for reporting only. It no longer gates the execution check --
# see stage1_execution_check for why.
MIN_DESTRUCTIVE_EVENTS = 50

# ---------------- Stage 2 config: did it attack the decoys? ----------------

# Decoy folders seeded in the CAPE guest (analysis user "admin").
DEFAULT_VICTIM_DIRS = [
    "\\Users\\admin\\Desktop",
    "\\Users\\admin\\Documents",
    "\\Users\\admin\\Downloads",
]

# Files that live inside the decoy folders but are not decoys: shell
# metadata, caches, profile data. Everything else under those folders is
# treated as a planted document.
#
# This replaced an allowlist of document extensions. The allowlist silently
# discarded any decoy whose type had not been anticipated: the decoy set
# contains real coursework files with extensions such as .vdfx and .2mdl,
# and excluding them cost 60% of the detected damage even for WannaCry
# (147 files actually destroyed vs 57 counted). An exclusion list fails in
# the safer direction -- an unlisted noise file inflates the count slightly,
# whereas an unlisted decoy type made real attacks invisible.
DECOY_NOISE_FRAGMENTS = [
    "\\appdata\\", "desktop.ini", "thumbs.db", "\\.ssh\\",
    "\\searches\\", "\\contacts\\", "\\favorites\\", "\\links\\",
    "ntuser.dat", "\\microsoft\\",
]

FILE_EVENT_TYPES = ["read", "write", "delete", "move", "copy", "execute"]
DESTRUCTIVE_EVENT_TYPES = ["write", "delete", "move"]

# Distinct decoy files that must be written, deleted or renamed before the
# run counts as real encryption.
#
# Counting distinct FILES rather than events is what makes this work across
# encryption styles. WannaCry reads a file, writes an encrypted copy and
# deletes the original -- several events per file. AvosLocker overwrites the
# file in place -- one event per file. Measured on the same decoy set, the
# event counts differed by more than an order of magnitude while the file
# counts stayed comparable, so an event threshold tuned on one style missed
# the other entirely.
#
# The value 3 sits in an empty band in the observed data: confirmed
# encrypting runs damaged 4, 13, 16, 17, 147 and 147 files, while every
# non-encrypting run damaged 0 or 1. It rests on only six positive examples
# and should be revisited once more confirmed runs exist.
MIN_DESTROYED_DECOY_FILES = 3

# Append-renames that count as encryption on their own, regardless of where
# they happened.
#
# The decoy check assumes the sample reaches Desktop, Documents or Downloads.
# Several families do not within the analysis window: one Cuba run renamed
# 4,890 files under Program Files and never got that far; a Clop run worked
# through AppData; SunCrypt went through System32. All were plainly
# encrypting and all scored zero decoy damage.
#
# Chosen from the labelled batch. Across 12 confirmed-encrypting runs the
# decoy check had missed, and 17 runs where nothing happened:
#
#     threshold 3  -> recovers 11/12, but wrongly flags 1 of the 17
#     threshold 8  -> recovers 10/12, wrongly flags none
#     threshold 20 -> recovers  8/12, wrongly flags none
#
# Eight is the point where recovery is highest at no cost. The two runs it
# still misses are genuinely ambiguous on this signal: one encrypting run
# made 4 append-renames while a non-encrypting one made 5, so no threshold
# separates them.
MIN_APPEND_RENAMES = 8

# The most a run's suffixes may vary before the append axis stops counting.
#
# A family appends a marker so it can recognise its own work later, so the
# suffixes converge: Cuba puts .cuba on everything, Clop puts .Clop. Across
# 1,349 encrypting runs with eight or more append-renames, every single one
# concentrated on a handful of suffixes -- not one had them mostly distinct.
#
# Ordinary software appending a different string each time is naming
# temporary files. Two benign programs were called encryption on exactly
# that basis: sixteen renames onto sixteen different suffixes, and nineteen
# onto ten. Requiring convergence excludes both and costs nothing, because
# nothing in the ransomware set looks like that.
MAX_SUFFIX_DIVERSITY = 0.3

# Renames onto one shared new extension needed before that counts on its own.
# Set well above what bulk conversion produces: a person converting a folder
# of images works in tens, while the runs this catches rename thousands.
MIN_SHARED_EXTENSION_RENAMES = 50

# Extensions ordinary software renames onto, excluded from the shared
# extension check so that build systems and editors do not register.
BENIGN_TARGET_EXTENSIONS = {
    "tmp", "bak", "old", "log", "part", "partial", "download", "crdownload",
    "swp", "orig", "sav", "~",
}

# A note whose name does not state its purpose has to appear in at least this
# many directories before it counts. Dropping one copy per directory is what
# separates a ransom note from an application's readme; measured on the
# labelled set, notes reached 2 or more directories in 36 of 57 confirmed
# encrypting runs and in 1 of 79 runs where nothing was encrypted -- and that
# one turned out to be encryption the manual pass had missed.
MIN_RANSOM_NOTE_DIRS = 2

# How many kinds of evidence must show something before a run counts as
# encryption on corroboration alone, with no single one reaching its own
# threshold.
#
# Each axis has a threshold set so that it is safe by itself, which makes
# each one blind just below that line: two destroyed decoy files, or four
# append-renames, or a note in one directory. Measured across the labelled
# set, that blindness is not symmetric. Of 79 runs where nothing was
# encrypted -- including ten that were thoroughly active, one of them writing
# 921 files -- not a single one registered on ANY axis. Every axis stayed at
# zero. Meanwhile 56 of 59 confirmed encrypting runs registered on at least
# one, and 51 on two or more.
#
# So a run showing faint traces on two independent axes is not two
# coincidences. It is the pattern the thresholds were built to catch, seen
# from just below each of them.
MIN_CORROBORATING_AXES = 2

# Minimum magnitude for an axis to count toward corroboration.
#
# Corroboration rests on the observation that no non-encrypting run in the
# labelled set registered on any axis at all, so two faint traces together
# were not two coincidences.
#
# The value is one, and an earlier note here argued it should be higher --
# that a single rename or one stray note is not evidence of anything. That
# note described an intention rather than the code, and the two are
# reconciled here in favour of the code, for a reason worth recording.
#
# Raising it was measured. Of 164 runs judged TRUE_ENCRYPTION in a labelled
# batch of 232, five were decided on corroboration alone. A threshold of
# three keeps two of those five and loses three; scaled to the full set that
# is roughly thirty-five encrypting runs reclassified as harmless.
#
# What it would buy is the exclusion of one constructed hard negative, a
# variant that dropped ransom notes and touched nothing else. That is a
# genuine weakness of this rule, and it is documented rather than fixed,
# because the trade is thirty-five real positives for one -- and because the
# hard negative in question is a program written for this experiment and run
# through a tool built to label ransomware. Its verdict is out-of-domain
# output, not a false positive by a detector.
#
# The note axis uses a literal 1 below rather than this constant: a note is
# a file that either appeared in a directory or did not, and requiring three
# of them in one directory would be requiring something different.
MIN_EVENTS_PER_AXIS = 1

MANIFEST_FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]


# ---------------- Report loading ----------------

def resolve_report_path(path):
    """Accept an analysis directory, a report.json, or a gzip archive."""
    p = Path(path)
    if p.is_dir():
        candidate = p / "reports" / "report.json"
        if candidate.exists():
            return candidate
        return None
    if p.is_file():
        return p
    return None


def batch_targets(base):
    """
    What to process in batch mode: analysis directories if there are any,
    otherwise archived reports sitting in the directory.
    """
    base = Path(base)

    # Only numerically named directories are analysis directories. Anything
    # else sharing the folder -- a stray copy, a subdirectory of notes --
    # would otherwise be taken as the whole batch, and the archives beside it
    # silently ignored. That happened: one unrelated directory in an archive
    # folder made 1,261 reports invisible and the run reported "0 of 0".
    dirs = sorted((d for d in base.iterdir() if d.is_dir() and d.name.isdigit()),
                   key=lambda d: int(d.name))
    if dirs:
        return dirs, False

    # Sorted by the task number inside the name rather than by the name, so
    # task_100 does not land after task_1000 the way text ordering puts it.
    archives = sorted(
        (p for p in base.iterdir()
         if p.is_file() and (p.suffix == ".gz" or p.name.endswith(".json"))),
        key=lambda p: (int(m.group(1))
                       if (m := re.search(r"task[_-]?(\d+)", p.name))
                       else 10**9, p.name))
    return archives, True


def load_report(report_path):
    """
    Read a report from a plain file or a gzip archive.

    The cleanup stage keeps only `task_<id>_report.json.gz`, and the verdict
    logic has been corrected nine times so far. Without being able to read
    those archives, every correction would apply only to analyses whose
    directories still happen to exist -- and would leave data collected on
    another machine frozen at whatever the logic said when it was first run.
    """
    path = Path(report_path)
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", errors="replace") as f:
                return json.load(f), None
        with open(path, "r", errors="replace") as f:
            return json.load(f), None
    except (json.JSONDecodeError, OSError) as e:
        return None, str(e)


# ---------------- Stage 1: execution check ----------------

def count_total_calls(report):
    total = 0
    for process in report.get("behavior", {}).get("processes", []) or []:
        total += len(process.get("calls", []) or [])
    return total


def count_file_events(report):
    """Count file events by type across the whole analysis (not decoy-limited)."""
    counts = defaultdict(int)
    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type in FILE_EVENT_TYPES:
            counts[event_type] += 1
    return counts


# Words that appear in ransom note filenames. Matching on the name alone
# would be noisy -- plenty of software ships a readme -- so the name is only
# half the test.
# Words that merely suggest a note. Software ships readmes, so these need
# corroboration -- either the file appearing across several directories, or
# one of the explicit words below.
RANSOM_NOTE_WORDS = [
    "readme", "read_me", "read-me", "read me",
    "recover", "restore", "decrypt", "unlock", "ransom", "instruction",
    "how_to", "howto", "how-to", "how to",
    "help_", "_info", "-info", "files_back", "your_files", "important",
    "attention", "warning",
]

# Separators are interchangeable in these names, and only some spellings were
# listed. One sample dropped "Read Me Please!.txt" into 83 directories and
# registered nothing, because the list held readme, read_me and read-me but
# not the spaced form. Rather than keep adding spellings, the name is
# normalised before matching: separators collapse away, so readme, read_me,
# read-me and "read me" all become the same string.
NOTE_SEPARATORS = str.maketrans({" ": "", "_": "", "-": "", ".": "", "!": ""})

# Words that state the purpose outright. Observed note names in this dataset
# include "#howtorecover.txt", "readme_to_decrypt.txt", "restore-my-files.txt"
# and "readmefordecrypt.txt"; no benign file in the labelled set carries one.
# A name like this is taken as sufficient on its own, because some families
# drop their note in a single directory and would otherwise go unnoticed.
RANSOM_NOTE_EXPLICIT = [
    "decrypt", "recover", "restore", "unlock", "ransom", "howto",
    "filesback", "yourfiles", "getback", "readmeplease",
]
# Extensions a ransom note will never have. This is an exclusion list rather
# than a list of permitted document types, because an allowlist only sees the
# formats someone thought of in advance: an earlier version listed txt, html,
# rtf and so on, and therefore missed three analyses whose note was named
# readme.md. The same mistake had already cost 60% of the observed damage
# when decoy files were filtered by extension.
NON_NOTE_EXTENSIONS = {
    "exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "com", "msi", "cab",
    "tmp", "log", "dat", "db", "sqlite", "etl", "evtx", "pf", "mui",
    # A shortcut holds no text, so it cannot be a note however it is named.
    # Windows ships one called "Backup and Restore (Windows 7).lnk", which
    # contains the word "restore" and was read as a note stating its purpose
    # -- enough on its own, under the explicit-name rule, to call a benign
    # run encryption.
    "lnk", "url", "ico", "cur", "ani", "theme", "deskthemepack",
}


def detect_ransom_notes(report):
    """
    Ransom notes, identified by the fact that the same file is written into
    many directories at once.

    The filename alone is a weak signal: readme.txt is ordinary. What is not
    ordinary is dropping an identically-named file into every directory the
    program touched. Ransomware does this so the victim finds the note
    wherever they look; nothing benign has a reason to.

    Returns the widest such spread found, plus the name responsible. A note
    seen in a single directory is reported but carries little weight.
    """
    by_basename = defaultdict(set)

    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        if event.get("event") not in ("write", "move"):
            continue

        # Unlike decoy damage, which is about the file that disappeared, a
        # ransom note is the file that appears -- so a move contributes its
        # destination here, where event_paths() returns its source.
        data = event.get("data", {}) or {}
        candidates = []
        if data.get("file"):
            candidates.append(data["file"])
        if data.get("to"):
            candidates.append(data["to"])

        for path in candidates:
            if not path:
                continue
            parts = path.replace("/", "\\").split("\\")
            if len(parts) < 2:
                continue
            basename = parts[-1].lower()
            directory = "\\".join(parts[:-1]).lower()

            ext = basename.rsplit(".", 1)[-1] if "." in basename else ""
            if ext in NON_NOTE_EXTENSIONS:
                continue
            flattened = basename.translate(NOTE_SEPARATORS)
            if not any(word.translate(NOTE_SEPARATORS) in flattened
                        for word in RANSOM_NOTE_WORDS):
                continue
            by_basename[basename].add(directory)

    if not by_basename:
        return {"ransom_note_dirs": 0, "ransom_note_name": "",
                "ransom_note_candidates": 0, "ransom_note_explicit": 0}

    # Prefer a name that states its purpose; otherwise the widest spread.
    explicit = {n: d for n, d in by_basename.items()
                if any(w.translate(NOTE_SEPARATORS) in n.translate(NOTE_SEPARATORS)
                        for w in RANSOM_NOTE_EXPLICIT)}
    source = explicit or by_basename
    name, dirs = max(source.items(), key=lambda kv: len(kv[1]))

    return {
        "ransom_note_dirs": len(dirs),
        "ransom_note_name": name[:60],
        "ransom_note_candidates": len(by_basename),
        "ransom_note_explicit": int(bool(explicit)),
    }


def count_shared_new_extension(report):
    """
    Files renamed onto one shared extension, whatever happened to the rest of
    the name.

    The append check requires the new name to begin with the old one, which
    is how Cuba (.cuba) and Clop (.Clop) work. Other families replace the
    name outright:

        A3DUtils.dll  ->  KCpJMTRFQkQftJKmayIH901lQ0TwALlR.[MrJeck@Cock.Li]

    Nothing of the original survives, so the append check sees nothing -- and
    in the run this comes from, 4,908 files were renamed this way and every
    axis read zero.

    What does survive is the extension. All 4,908 landed on the same one, and
    that is the part worth counting: a rename that gives many files an
    identical new suffix is the signature of encryption regardless of what it
    did to the stem. Ordinary software converting files in bulk would share
    an extension too, which is why this counts renames onto an extension the
    file did not already have, and why the threshold is set where a handful
    of conversions cannot reach it.

    Returns (count on the most common new extension, that extension).
    """
    by_extension = defaultdict(int)

    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file" or event.get("event") != "move":
            continue
        data = event.get("data", {}) or {}
        src, dst = data.get("from"), data.get("to")
        if not src or not dst:
            continue

        src_name = src.replace("/", "\\").split("\\")[-1]
        dst_name = dst.replace("/", "\\").split("\\")[-1]
        if "." not in dst_name:
            continue

        dst_ext = dst_name[dst_name.index("."):].lower()
        src_ext = src_name[src_name.index("."):].lower() if "." in src_name else ""
        if dst_ext == src_ext:
            continue

        # Appending a suffix also produces a new extension, so without this
        # the append check and this one count the same rename, and any
        # append-renaming run reaches two axes by itself. This exists for the
        # renames the append check cannot see: those that discard the stem.
        if dst.startswith(src):
            continue
        # Bare numbers are log rotation and backup numbering -- app.log
        # becomes app.log.1. A family needs a marker it can recognise later.
        if dst_ext.lstrip(".").isdigit():
            continue
        # Extensions ordinary software renames onto in bulk.
        if dst_ext.lstrip(".") in BENIGN_TARGET_EXTENSIONS:
            continue

        by_extension[dst_ext] += 1

    if not by_extension:
        return 0, ""
    ext, n = max(by_extension.items(), key=lambda kv: kv[1])
    return n, ext[:40]


def count_append_renames(report):
    """
    Renames that keep the original filename intact and append a suffix:
    file.docx -> file.docx.cuba

    This is measured because the decoy-based check has a structural blind
    spot. It assumes the sample reaches the decoy folders, and several
    families do not within the analysis window -- one Cuba run renamed 4,779
    files under Program Files/Adobe and never touched Desktop or Documents,
    so it scored zero despite plainly encrypting.

    Append-renaming is location-independent, which is the point. It is also
    family-independent in a way that matching a specific extension is not:
    Cuba appends ".cuba" to every file, Clop appends ".Clop", but SunCrypt
    appends a different 64-character hash per file, so counting files sharing
    one new extension would miss it entirely. What they have in common is the
    shape of the rename, not the string.

    Normal software rarely does this. Temporary files are renamed to a
    different name rather than an extended one, and backup tools tend to
    insert rather than append. Log rotation is the notable exception
    (app.log -> app.log.1), which is why the count matters and not merely
    its presence.

    Returned but NOT yet used in the verdict: the threshold should come from
    the observed distribution against labelled data, not from guesswork.
    """
    total = 0
    suffixes = defaultdict(int)

    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file" or event.get("event") != "move":
            continue
        data = event.get("data", {}) or {}
        src, dst = data.get("from"), data.get("to")
        if not src or not dst:
            continue
        if dst.startswith(src) and len(dst) > len(src):
            total += 1
            suffixes[dst[len(src):]] += 1

    # The same transformation is often not recorded as a move at all. One
    # family writes X.exe and separately deletes X, which leaves no move
    # event and so scored zero append-renames despite doing this to 45 files,
    # every original deleted. Reconstructing the pairs from the summary lists
    # catches that: a written path that extends a deleted path is a rename
    # however the sandbox chose to log it.
    summary = report.get("behavior", {}).get("summary", {}) or {}
    written = {p for p in (summary.get("write_files") or []) if isinstance(p, str)}
    deleted = {p for p in (summary.get("delete_files") or []) if isinstance(p, str)}

    if written and deleted:
        # Index by directory so each written path is only compared against
        # deletions from the same place, rather than every deletion.
        by_dir = defaultdict(list)
        for path in deleted:
            by_dir[path.rsplit("\\", 1)[0] if "\\" in path else ""].append(path)

        for path in written:
            directory = path.rsplit("\\", 1)[0] if "\\" in path else ""
            for original in by_dir.get(directory, ()):
                if path != original and path.startswith(original) and len(path) > len(original):
                    total += 1
                    suffixes[path[len(original):]] += 1
                    break

    return total, len(suffixes), dict(suffixes)


def stage1_execution_check(report):
    """Returns (executed: bool, stats: dict)."""
    total_calls = count_total_calls(report)
    file_counts = count_file_events(report)
    destructive = sum(file_counts.get(t, 0) for t in DESTRUCTIVE_EVENT_TYPES)

    stats = {
        "total_calls": total_calls,
        "destructive_events": destructive,
        "file_reads": file_counts.get("read", 0),
        "file_writes": file_counts.get("write", 0),
        "file_deletes": file_counts.get("delete", 0),
        "file_moves": file_counts.get("move", 0),
    }

    # Only the call count decides whether the sample executed. The number of
    # destructive file events used to be part of this test, which conflated
    # two separate questions: "did this run?" and "did this do damage?".
    #
    # The effect was large. Of 229 runs marked FAILED, 70 had executed
    # substantially -- one made 77,356 API calls -- and were recorded as
    # having never started, simply because they destroyed few files. That is
    # what NO_VICTIM_ACTIVITY is for, and it matters: "ran but did not
    # encrypt" is a finding about the sample, while "never ran" is a finding
    # about the sandbox. Merging them puts sandbox failures into the
    # denominator of any trigger rate.
    executed = total_calls >= MIN_TOTAL_CALLS
    return executed, stats


# ---------------- Stage 2: victim-file check ----------------

def event_paths(event):
    """
    Paths involved in a file event.

    Most events carry a single path in data.file, but a move carries
    data.from and data.to instead -- data.file is absent. Reading only
    data.file therefore discarded every move event, and move is precisely
    how several ransomware families encrypt: the original is renamed to an
    encrypted counterpart (file.docx -> file.docx.cipher4). In one analysis
    240 move events were dropped this way, which is why runs that had
    visibly encrypted the decoys reported zero damage.

    For a move, the SOURCE is what matters: the decoy file ceased to exist
    under its own name. The destination is the attacker's new artefact, and
    counting it as well would double the tally for a single file.
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


def path_in_victim_dirs(path, victim_dirs):
    """Inside a decoy folder and not one of the known non-decoy files."""
    if not path:
        return False
    lowered = path.lower()
    if not any(v.lower() in lowered for v in victim_dirs):
        return False
    return not any(noise in lowered for noise in DECOY_NOISE_FRAGMENTS)


def stage2_victim_check(report, victim_dirs):
    """
    Returns (destroyed_files, read_only_files, destructive_events, per_type_counts).

    destroyed_files is the primary signal: distinct decoy paths that were
    written, deleted or renamed.

    read_only_files is tracked separately and deliberately excluded from the
    verdict. An archiver reads every document in the decoy folders without
    harming any of them -- the 7-Zip run read 56 decoys and destroyed none.
    Counting reads would classify that as encryption.
    """
    victim_counts = defaultdict(int)
    removed_paths = set()      # gone: deleted or renamed away
    written_paths = set()      # written to, whether or not it existed before
    read_paths = set()

    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type not in FILE_EVENT_TYPES:
            continue
        for path in event_paths(event):
            if not path_in_victim_dirs(path, victim_dirs):
                continue
            victim_counts[event_type] += 1
            if event_type in ("delete", "move"):
                removed_paths.add(path)
            elif event_type == "write":
                written_paths.add(path)
            elif event_type == "read":
                read_paths.add(path)

    # What counts as harming a decoy.
    #
    # Overwriting in place has to count: AvosLocker replaces the contents and
    # leaves the name alone, and dropping that would put it back among the
    # misses. But "an event occurred on a path inside a decoy folder" is a
    # weaker claim than "a decoy was harmed", and three harmless programs were
    # called encryption on the weaker one -- a note dropped into each folder,
    # a copy written beside each document, and Word, whose ~$ lock files are
    # created and deleted next to whatever is open.
    #
    # None of them touched a file that was already there. Two conditions
    # separate the cases:
    #
    #   a write destroys only if the path was also read, since replacing
    #   contents requires having had them, and creating a file does not;
    #
    #   a deletion destroys only if the run did not create the file first,
    #   since removing one's own scratch file leaves the folder as it was.
    self_created = written_paths - read_paths
    destroyed_paths = (removed_paths - self_created) | (written_paths & read_paths)
    read_paths -= destroyed_paths
    destructive_events = sum(victim_counts.get(t, 0) for t in DESTRUCTIVE_EVENT_TYPES)
    return len(destroyed_paths), len(read_paths), destructive_events, dict(victim_counts)


# ---------------- Combined verdict ----------------

def analyze(report, victim_dirs):
    """Run both stages and return a result dict."""
    executed, stats = stage1_execution_check(report)
    n_append, n_suffixes, _ = count_append_renames(report)
    stats["append_renames"] = n_append
    stats["distinct_rename_suffixes"] = n_suffixes

    n_shared_ext, shared_ext = count_shared_new_extension(report)
    stats["shared_extension_renames"] = n_shared_ext
    stats["shared_extension"] = shared_ext
    stats.update(detect_ransom_notes(report))
    note_dirs = stats.get("ransom_note_dirs", 0)
    note_explicit = stats.get("ransom_note_explicit", 0)

    destroyed, read_only, destructive_events, victim_counts = stage2_victim_check(
        report, victim_dirs)

    # Independent kinds of evidence, each needing enough events to mean
    # something. Counting any non-zero value worked while there were three
    # axes -- no non-encrypting run registered on any of them -- but a fourth
    # axis made accidental pairs reachable: a build system renaming onto .tmp
    # beside a readme.md, or a log rotation producing app.log.1 to .4.
    corroborating_axes = sum([destroyed >= MIN_EVENTS_PER_AXIS,
                               n_append >= MIN_EVENTS_PER_AXIS,
                               note_dirs >= 1,
                               n_shared_ext >= MIN_EVENTS_PER_AXIS])
    stats["corroborating_axes"] = corroborating_axes

    # Two independent kinds of evidence, either of which settles it.
    #
    # Decoy damage is the stronger signal but only fires if the sample got as
    # far as the decoy folders. Append-renaming fires wherever the sample was
    # working, so it catches families that spend the whole window elsewhere.
    # They are checked before the execution gate because a run can be judged
    # to have "not executed" on call counts while still having renamed files,
    # and a rename is direct evidence that encryption happened.
    if destroyed >= MIN_DESTROYED_DECOY_FILES:
        verdict = "TRUE_ENCRYPTION"
        reason = f"destroyed {destroyed} decoy files"
    elif (n_append >= MIN_APPEND_RENAMES
            and n_suffixes / max(1, n_append) <= MAX_SUFFIX_DIVERSITY):
        verdict = "TRUE_ENCRYPTION"
        reason = (f"{n_append} append-renames outside the decoy folders "
                  f"({n_suffixes} distinct suffix"
                  f"{'es' if n_suffixes != 1 else ''})")
    elif n_shared_ext >= MIN_SHARED_EXTENSION_RENAMES:
        verdict = "TRUE_ENCRYPTION"
        reason = (f"{n_shared_ext} files renamed onto '{shared_ext}', "
                  f"replacing whatever extension they had")
    elif corroborating_axes >= MIN_CORROBORATING_AXES:
        verdict = "TRUE_ENCRYPTION"
        reason = (f"corroborating evidence on {corroborating_axes} axes "
                  f"({destroyed} decoy files, {n_append} append-renames, "
                  f"note in {note_dirs}), none conclusive alone")
    elif note_explicit or note_dirs >= MIN_RANSOM_NOTE_DIRS:
        # A third kind of evidence, independent of both file damage and
        # renaming: the demand itself. It catches families that encrypt
        # somewhere the decoy check cannot see and rename in a way the
        # append check cannot read.
        verdict = "TRUE_ENCRYPTION"
        reason = (f"ransom note '{stats.get('ransom_note_name','')}' in "
                  f"{note_dirs} director{'ies' if note_dirs != 1 else 'y'}")
    elif not executed:
        verdict = "FAILED"
        reason = (f"did not execute (calls={stats['total_calls']}, "
                  f"below {MIN_TOTAL_CALLS})")
    elif destroyed > 0:
        verdict = "WEAK_VICTIM_ACTIVITY"
        reason = f"only {destroyed} decoy file(s) destroyed"
    elif read_only > 0:
        verdict = "NO_VICTIM_ACTIVITY"
        reason = f"read {read_only} decoy files but destroyed none"
    else:
        verdict = "NO_VICTIM_ACTIVITY"
        reason = "ran but never touched decoy files (self-unpack / evasion)"

    return {
        "verdict": verdict,
        "reason": reason,
        **stats,
        "destroyed_decoy_files": destroyed,
        "read_only_decoy_files": read_only,
        "destructive_victim_events": destructive_events,
        "victim_reads": victim_counts.get("read", 0),
        "victim_writes": victim_counts.get("write", 0),
        "victim_deletes": victim_counts.get("delete", 0),
        "victim_moves": victim_counts.get("move", 0),
    }


# ---------------- Sample identity (for manifest linking) ----------------

def get_sample_sha256(report):
    """CAPE records the submitted file's hashes under target.file."""
    target = report.get("target", {}) or {}
    file_info = target.get("file", {}) or {}
    return file_info.get("sha256", "")


def get_cape_metadata(report):
    """
    CAPE's own assessment of the sample, which is independent of our
    behavioural verdict and worth recording alongside it:
      - malscore: CAPE's aggregate maliciousness score
      - family: the family CAPE's signature set attributed the sample to
    """
    malscore = report.get("malscore")
    family = "unknown"
    detections = report.get("detections", [])
    if isinstance(detections, list) and detections:
        first = detections[0]
        if isinstance(first, dict):
            family = first.get("family", "unknown")
    return {
        "malscore": malscore if malscore is not None else "",
        "cape_family": family,
    }


def get_task_id(report, fallback_path):
    """CAPE records the analysis id under info.id; fall back to directory name."""
    info = report.get("info", {}) or {}
    task_id = info.get("id")
    if task_id:
        return str(task_id)
    path = Path(fallback_path)

    # .../analyses/<id>/reports/report.json
    parts = path.parts
    if "analyses" in parts:
        idx = parts.index("analyses")
        if idx + 1 < len(parts):
            return parts[idx + 1]

    # task_137_report.json.gz, as written by the cleanup stage
    match = re.search(r"task[_-]?(\d+)", path.name)
    if match:
        return match.group(1)
    return ""


# ---------------- Manifest update ----------------

def load_manifest(manifest_path):
    if not manifest_path or not os.path.exists(manifest_path):
        return {}
    entries = {}
    with open(manifest_path, newline="") as f:
        for row in csv.DictReader(f):
            entries[row["sha256"]] = row
    return entries


def save_manifest(manifest_path, entries):
    with open(manifest_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDNAMES)
        writer.writeheader()
        for _sha, row in sorted(entries.items(), key=lambda kv: kv[1].get("added_date", "")):
            writer.writerow({k: row.get(k, "") for k in MANIFEST_FIELDNAMES})


def update_manifest(manifest_path, sha256, task_id, verdict):
    """Record the verdict against the sample. Returns True if updated."""
    if not manifest_path or not sha256:
        return False
    entries = load_manifest(manifest_path)
    if sha256 not in entries:
        return False
    entries[sha256]["status"] = "analyzed"
    entries[sha256]["result"] = verdict
    if task_id and not entries[sha256].get("cape_task_id"):
        entries[sha256]["cape_task_id"] = task_id
    save_manifest(manifest_path, entries)
    return True


# ---------------- Runners ----------------

RESULT_FIELDNAMES = [
    "task_id", "sha256", "verdict", "reason",
    "malscore", "cape_family",
    "total_calls", "destructive_events",
    "file_reads", "file_writes", "file_deletes", "file_moves",
    "destroyed_decoy_files", "read_only_decoy_files", "destructive_victim_events",
    "append_renames", "distinct_rename_suffixes",
    "ransom_note_dirs", "ransom_note_name", "ransom_note_candidates",
    "ransom_note_explicit", "corroborating_axes",
    "shared_extension_renames", "shared_extension",
]


def _analyze_for_pool(path, victim_dirs):
    """
    Worker entry point. Defined at module level because a process pool has to
    pickle the callable, which rules out a closure or a lambda.
    """
    try:
        return analyze_one(path, victim_dirs, manifest_path=None, quiet=True)
    except Exception as e:
        print(f"\n   [!] {path}: {type(e).__name__}: {e}")
        return None


def analyze_one(path, victim_dirs, manifest_path=None, quiet=False):
    report_path = resolve_report_path(path)
    if not report_path:
        if not quiet:
            print(f"[!] no report.json found at {path}")
        return None

    report, err = load_report(report_path)
    if err:
        if not quiet:
            print(f"[!] {report_path}: {err}")
        return None

    result = analyze(report, victim_dirs)
    result["sha256"] = get_sample_sha256(report)
    result["task_id"] = get_task_id(report, report_path)
    result.update(get_cape_metadata(report))

    if manifest_path:
        update_manifest(manifest_path, result["sha256"], result["task_id"], result["verdict"])

    return result


def print_single(result):
    print("=" * 60)
    print(f"Task {result['task_id']}  sha256={result['sha256'][:16] or '(unknown)'}...")
    print(f"CAPE malscore={result.get('malscore', '')}  "
          f"family={result.get('cape_family', 'unknown')}")
    print("=" * 60)
    print(f"\n[Stage 1: execution]")
    print(f"   total API calls     : {result['total_calls']}")
    print(f"   destructive events  : {result['destructive_events']}")
    print(f"   read/write/del/move : {result['file_reads']}/{result['file_writes']}"
          f"/{result['file_deletes']}/{result['file_moves']}")

    if result["verdict"] != "FAILED":
        print(f"\n[Stage 2: decoy files]")
        print(f"   decoy files destroyed  : {result['destroyed_decoy_files']}"
              f" (threshold {MIN_DESTROYED_DECOY_FILES})")
        print(f"   decoy files only read  : {result['read_only_decoy_files']}"
              f"  (reads alone never count as encryption)")
        print(f"   destructive events     : {result['destructive_victim_events']}")
    else:
        print(f"\n[Stage 2: decoy files] skipped (sample did not execute)")

    # Always shown. A run judged FAILED or NO_VICTIM can still have renamed
    # thousands of files outside the decoy folders, which is exactly the case
    # this measurement exists to surface.
    print(f"\n[Encryption outside the decoy folders]")
    print(f"   append-renames          : {result.get('append_renames', 0)}"
          f"  (threshold {MIN_APPEND_RENAMES}; file.docx -> file.docx.suffix)")
    print(f"   distinct new suffixes   : {result.get('distinct_rename_suffixes', 0)}"
          f"  (1 = one shared family extension; many = a per-file hash)")

    n_shared = result.get("shared_extension_renames", 0)
    if n_shared:
        print(f"   renamed onto one extension : {n_shared} files -> "
              f"'{result.get('shared_extension','')}'  "
              f"(threshold {MIN_SHARED_EXTENSION_RENAMES})")

    axes = result.get("corroborating_axes", 0)
    print(f"\n[Corroboration]")
    print(f"   axes with at least {MIN_EVENTS_PER_AXIS} events : {axes}/4"
          f"  (threshold {MIN_CORROBORATING_AXES} when none is conclusive alone)")

    note_dirs = result.get("ransom_note_dirs", 0)
    print(f"\n[Ransom note]")
    if note_dirs:
        explicit = result.get("ransom_note_explicit", 0)
        print(f"   '{result.get('ransom_note_name','')}' written into {note_dirs} "
              f"director{'ies' if note_dirs != 1 else 'y'}"
              f"{'  [name states its purpose]' if explicit else ''}")
        if note_dirs < MIN_RANSOM_NOTE_DIRS and not explicit:
            print(f"   (one directory and a generic name -- could be an ordinary readme)")
    else:
        print(f"   none found")

    print(f"\n[Verdict] {result['verdict']}")
    print(f"   {result['reason']}")
    if result["verdict"] == "TRUE_ENCRYPTION":
        print(f"   -> proceed to feature extraction")
    else:
        print(f"   -> not usable for feature extraction")


def run_batch(analyses_dir, victim_dirs, out_csv, manifest_path, list_passed,
              workers=1):
    base = Path(analyses_dir)
    if not base.is_dir():
        print(f"[!] not a directory: {analyses_dir}")
        sys.exit(1)

    # Analysis directories are numeric task ids. Where the cleanup stage has
    # already removed them, the archived reports are read instead, so a
    # corrected verdict can still be applied to work that has been tidied up
    # or handed over from another machine.
    subdirs, from_archives = batch_targets(base)
    if from_archives:
        print(f"No analysis directories here; reading {len(subdirs)} archived "
              f"reports instead\n")

    # Reports run to a hundred megabytes each and parsing one is a couple of
    # seconds of pure CPU, so a few thousand of them takes half an hour on one
    # core. Each report is independent, which makes this the easiest kind of
    # work to spread out: hand each one to a worker and collect the verdicts.
    #
    # The manifest is deliberately not written from the workers -- concurrent
    # writes to one CSV would corrupt it. Batch mode already leaves the
    # manifest alone and only reports.
    results = []
    if workers and workers > 1 and len(subdirs) > 1:
        from concurrent.futures import ProcessPoolExecutor
        from functools import partial
        work = partial(_analyze_for_pool, victim_dirs=victim_dirs)
        print(f"Parsing {len(subdirs)} reports across {workers} processes\n")
        with ProcessPoolExecutor(max_workers=workers) as pool:
            done = 0
            for r in pool.map(work, [str(d) for d in subdirs], chunksize=4):
                done += 1
                if done % 50 == 0 or done == len(subdirs):
                    print(f"\r   {done}/{len(subdirs)}", end="", flush=True)
                if r:
                    results.append(r)
        print()
        results.sort(key=lambda r: (len(str(r.get("task_id", ""))),
                                     str(r.get("task_id", ""))))
    else:
        for d in subdirs:
            r = analyze_one(d, victim_dirs, manifest_path, quiet=True)
            if r:
                results.append(r)

    if list_passed:
        for r in results:
            if r["verdict"] == "TRUE_ENCRYPTION":
                print(r["task_id"])
        return results

    header = (f"{'task':<7} {'verdict':<22} {'family':<16} {'calls':>7} "
              f"{'DESTROYED':>10} {'read':>6} {'appendRen':>10} {'sfx':>5} {'note':>6} {'sharedX':>7} {'axes':>5}")
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r['task_id']:<7} {r['verdict']:<22} {str(r.get('cape_family',''))[:14]:<16} "
              f"{r['total_calls']:>7} "
              f"{r.get('destroyed_decoy_files', 0):>10} "
              f"{r.get('read_only_decoy_files', 0):>6} "
              f"{r.get('append_renames', 0):>10} "
              f"{r.get('distinct_rename_suffixes', 0):>5} "
              f"{r.get('ransom_note_dirs', 0):>6} "
              f"{r.get('shared_extension_renames', 0):>7} "
              f"{r.get('corroborating_axes', 0):>5}")

    counts = defaultdict(int)
    for r in results:
        counts[r["verdict"]] += 1
    print("\n[summary] " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    passed = [r for r in results if r["verdict"] == "TRUE_ENCRYPTION"]
    print(f"[usable]  {len(passed)} of {len(results)} analyses proceed to feature extraction")

    if out_csv:
        with open(out_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=RESULT_FIELDNAMES)
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, "") for k in RESULT_FIELDNAMES})
        print(f"[saved]   {out_csv}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Combined execution + encryption verdict for CAPE analyses.")
    parser.add_argument("path", nargs="?",
                         help="An analysis directory or a report.json")
    parser.add_argument("--batch", metavar="ANALYSES_DIR",
                         help="Process every analysis under this directory")
    parser.add_argument("--out", default=None, help="CSV output for batch mode")
    parser.add_argument("--manifest", default=None,
                         help="Manifest CSV to update with verdicts automatically")
    parser.add_argument("--victim-dirs", nargs="+", default=DEFAULT_VICTIM_DIRS,
                         help="Decoy folder path fragments in the guest")
    parser.add_argument("--workers", type=int, default=1, metavar="N",
                         help="Parse this many reports at once in batch mode. Each is "
                              "independent, so this scales with physical cores; on a "
                              "machine also running the sandbox, leave it at 1 or 2 so "
                              "the guests keep their CPU.")
    parser.add_argument("--list-passed", action="store_true",
                         help="Print only the task ids that reached TRUE_ENCRYPTION")
    args = parser.parse_args()

    if args.batch:
        run_batch(args.batch, args.victim_dirs, args.out, args.manifest,
                  args.list_passed, workers=args.workers)
    elif args.path:
        result = analyze_one(args.path, args.victim_dirs, args.manifest)
        if result:
            print_single(result)
            sys.exit(0 if result["verdict"] == "TRUE_ENCRYPTION" else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
