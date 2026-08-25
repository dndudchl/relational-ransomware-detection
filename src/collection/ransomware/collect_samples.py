#!/usr/bin/env python3
"""
collect_samples.py - Automated ransomware sample collection from
MalwareBazaar, with manifest-based duplicate prevention.

What it does
------------
For each malware family given:
  1. Query MalwareBazaar's API for recent samples of that family
     (query=get_siginfo).
  2. Check each returned sha256 against the local manifest CSV. Samples
     already collected (or already submitted/analyzed) are skipped, so we
     never re-download or re-submit the same binary. This addresses a real
     problem from earlier in the project, where three legacy reports turned
     out to be the same sample and it was only noticed by accident.
  3. Download the new ones (query=get_file). MalwareBazaar serves samples
     as ZIP archives password-protected with "infected" to prevent
     accidental execution.
  4. Extract each archive into the samples directory, named by sha256.
  5. Register the sample in the manifest with family/source metadata and
     status=pending, ready for CAPE submission.

Family prioritisation
---------------------
Empirically, the families most likely to actually detonate in our sandbox
are the ones we have already observed detonating: Cuba, Babuk, RansomEXX,
AvosLocker, SunCrypt (all confirmed TRUE_ENCRYPTION in the legacy Cuckoo
dataset). Families known to be heavily packed or to resolve APIs at
runtime (notably Conti) have a much lower success rate and are lower
priority. Pass whichever families you want as arguments.

Security notes
--------------
- The Auth-Key is read from the MB_AUTH_KEY environment variable and is
  NEVER written to disk or committed. Do not hardcode it.
- Downloaded files are real malware. Keep the samples directory outside
  any synced/backed-up folder, exclude it from antivirus, and never mark
  the files executable on the host. They exist only to be submitted to
  the sandbox VM.
- The manifest contains only hashes and metadata, so it is safe to commit.

Requirements
------------
  pip install requests pyzipper
(pyzipper is needed because MalwareBazaar's archives use AES encryption,
which Python's built-in zipfile module cannot decrypt.)

Usage
-----
  export MB_AUTH_KEY="your-key-here"

  # List what's available without downloading (safe dry run)
  python3 collect_samples.py --families Cuba Babuk --limit 10 --dry-run

  # Actually download new samples
  python3 collect_samples.py --families Cuba Babuk RansomEXX \\
      --limit 10 --samples-dir ~/samples --manifest manifest.csv

  # Restrict to a file type (recommended: exe, since our CAPE pipeline
  # submits with --package exe)
  python3 collect_samples.py --families Cuba --limit 20 --file-type exe
"""

import os
import re
import sys
import csv
import time
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"

# CAPE submission. CAPE runs as its own user and its dependencies live in a
# poetry environment, so submission goes through sudo. The poetry binary is
# not on the default PATH for that user, hence the absolute path.
DEFAULT_CAPE_DIR = "/opt/CAPEv2"
DEFAULT_POETRY_BIN = "/etc/poetry/bin/poetry"
DEFAULT_STAGING_DIR = "/tmp"

# CAPE's submit.py prints the assigned task id in a line such as
#   Success: File "/tmp/x.exe" added as task with ID 61
# The id is what links a manifest row to its analysis directory.
TASK_ID_PATTERN = re.compile(r"(?:task with ID|Task ID:?)\s*(\d+)", re.IGNORECASE)

# Manifest schema must stay in sync with manifest.py
FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]

# How many times a sample may fail submission before it is set aside.
MAX_SUBMIT_ATTEMPTS = 3

# Default upper bound on sample size, in bytes.
#
# This must stay aligned with max_sample_size in CAPE's web.conf. CAPE drops
# anything larger during demux, and submit.py then reports only a bare
# "Error: adding task to database", so an oversized sample looks like a
# mysterious failure rather than a size rejection. Filtering at download time
# keeps the two limits together: whatever gets downloaded can be submitted.
#
# Set to 50 MB to match a raised web.conf. Changing it here alone is not
# enough -- web.conf must agree, or oversized samples will download and then
# fail to submit.
DEFAULT_MAX_SAMPLE_BYTES = 50_000_000


def count_submit_attempts(notes):
    """Read the attempt counter previously stored in the notes field."""
    match = re.search(r"submit_failed_x(\d+)", notes or "")
    return int(match.group(1)) if match else 0


def strip_attempt_marker(notes):
    return re.sub(r";?submit_failed_x\d+", "", notes or "")


# Families we have empirically observed detonating successfully.
SUGGESTED_FAMILIES = ["Cuba", "Babuk", "RansomEXX", "AvosLocker", "SunCrypt"]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_manifest(manifest_path):
    if not os.path.exists(manifest_path):
        return {}
    entries = {}
    with open(manifest_path, newline="") as f:
        for row in csv.DictReader(f):
            sha = row.get("sha256")
            if not sha:
                continue
            # csv.DictReader fills missing trailing columns with None, and a
            # dict.get default does not apply when the key exists with a None
            # value. That is enough to break sorting, which compares
            # added_date against a string. Several tools rewrite this file, so
            # one of them leaving a short row behind should not stop
            # collection; normalising here makes every consumer safe.
            entries[sha] = {k: ("" if v is None else v) for k, v in row.items()}
    return entries


def save_manifest(manifest_path, entries):
    with open(manifest_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for sha, row in sorted(entries.items(),
                                key=lambda kv: kv[1].get("added_date") or ""):
            writer.writerow({k: (row.get(k) or "") for k in FIELDNAMES})


def get_auth_key():
    key = os.environ.get("MB_AUTH_KEY")
    if not key:
        print("[!] MB_AUTH_KEY environment variable is not set.")
        print("    Get a free key at https://auth.abuse.ch/ then run:")
        print('      export MB_AUTH_KEY="your-key-here"')
        sys.exit(1)
    return key


def query_family(session, auth_key, family, limit):
    """Query MalwareBazaar for recent samples of a given family signature."""
    try:
        response = session.post(
            API_URL,
            data={"query": "get_siginfo", "signature": family, "limit": str(limit)},
            headers={"Auth-Key": auth_key},
            timeout=30,
        )
    except Exception as e:
        print(f"   [!] request failed for {family}: {e}")
        return []

    if response.status_code != 200:
        print(f"   [!] HTTP {response.status_code} for {family}")
        return []

    try:
        payload = response.json()
    except ValueError:
        print(f"   [!] non-JSON response for {family}")
        return []

    status = payload.get("query_status")
    if status != "ok":
        # Common statuses: no_results, signature_not_found, illegal_signature
        print(f"   [!] query_status={status} for {family}")
        return []

    return payload.get("data", []) or []


def query_tag(session, auth_key, tag, limit):
    """
    Query MalwareBazaar by tag rather than by family signature.

    The two queries cover different ground. A signature query returns that
    family's whole inventory (MedusaLocker has 71 samples on the platform, so
    asking for 1000 returns all 71). A tag query returns the most recent
    samples carrying the tag, across all families, capped at 1000.

    So a tag query gives breadth -- including families we would not have
    thought to name -- while signature queries give depth on families we
    already care about. Neither replaces the other.
    """
    try:
        response = session.post(
            API_URL,
            data={"query": "get_taginfo", "tag": tag, "limit": str(limit)},
            headers={"Auth-Key": auth_key},
            timeout=60,
        )
    except Exception as e:
        print(f"   [!] request failed for tag {tag}: {e}")
        return []

    if response.status_code != 200:
        print(f"   [!] HTTP {response.status_code} for tag {tag}")
        return []

    try:
        payload = response.json()
    except ValueError:
        print(f"   [!] non-JSON response for tag {tag}")
        return []

    status = payload.get("query_status")
    if status != "ok":
        print(f"   [!] query_status={status} for tag {tag}")
        return []

    return payload.get("data", []) or []


def family_of(entry, fallback=""):
    """
    Family for a sample. Signature queries know it from the query itself;
    tag queries have to read it from the entry, where it may be absent
    because MalwareBazaar could not attribute the sample to a family.
    """
    sig = (entry.get("signature") or "").strip()
    return sig if sig else fallback


def download_sample(session, auth_key, sha256):
    """Download one sample by sha256. Returns raw zip bytes, or None."""
    try:
        response = session.post(
            API_URL,
            data={"query": "get_file", "sha256_hash": sha256},
            headers={"Auth-Key": auth_key},
            timeout=60,
        )
    except Exception as e:
        print(f"      [!] download failed: {e}")
        return None

    if response.status_code != 200:
        print(f"      [!] HTTP {response.status_code}")
        return None

    content = response.content
    # An error is returned as JSON; a real sample is a binary zip.
    if content[:2] != b"PK":
        try:
            import json
            err = json.loads(content.decode("utf-8", "ignore"))
            print(f"      [!] API error: {err.get('query_status', content[:100])}")
        except Exception:
            print(f"      [!] unexpected response (not a zip)")
        return None

    return content


def extract_sample(zip_bytes, sha256, samples_dir):
    """Extract the password-protected archive. Returns extracted path or None."""
    try:
        import pyzipper
    except ImportError:
        print("      [!] pyzipper not installed (pip install pyzipper)")
        return None

    import io
    tmp_zip = samples_dir / f"{sha256}.zip"
    tmp_zip.write_bytes(zip_bytes)

    try:
        with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.setpassword(ZIP_PASSWORD)
            names = zf.namelist()
            if not names:
                print("      [!] archive is empty")
                return None
            # MalwareBazaar archives contain a single file named by hash
            data = zf.read(names[0])
    except Exception as e:
        print(f"      [!] extraction failed: {e}")
        return None
    finally:
        tmp_zip.unlink(missing_ok=True)

    out_path = samples_dir / sha256
    out_path.write_bytes(data)
    # Ensure it is not executable on the host; it is only for sandbox submission.
    os.chmod(out_path, 0o600)
    return out_path


def submit_to_cape(sample_path, sha256, cape_dir, poetry_bin, staging_dir,
                    timeout, machine=None, route=None, enforce_timeout=False,
                    package=None, dry_run=False):
    """
    Submit one sample to CAPE and return the assigned task id, or None.

    Two details make this awkward enough to be worth encapsulating:

    1. Ownership. Samples are downloaded as the current user with mode 0600,
       but CAPE runs as the `cape` user and must be able to read the file.
       Rather than loosening permissions on the collection directory, the
       sample is copied to a staging path readable by CAPE. It is copied
       WITHOUT the execute bit so it cannot be run accidentally on the host;
       execution only ever happens inside the guest VM.

    2. Environment. CAPE's dependencies live in a poetry environment and
       poetry is not on the `cape` user's default PATH, so it is invoked by
       absolute path from inside the CAPE directory.
    """
    staged = Path(staging_dir) / f"{sha256[:16]}.exe"

    # Both "python" and "python3" resolve inside the poetry environment on
    # this host; python3 is used because that is what the first successful
    # automated submission ran with.
    cmd_str = f"cd {cape_dir} && {poetry_bin} run python3 utils/submit.py"
    if machine:
        cmd_str += f" --machine {machine}"
    if route:
        cmd_str += f" --route {route}"
    cmd_str += f" --timeout {timeout}"
    if enforce_timeout:
        cmd_str += " --enforce-timeout"
    if package:
        cmd_str += f" --package {package}"
    cmd_str += f" {staged}"
    full_cmd = ["sudo", "-u", "cape", "bash", "-c", cmd_str]

    if dry_run:
        print(f"      [dry-run] would stage to {staged} and run: {' '.join(full_cmd)}")
        return None

    try:
        shutil.copyfile(sample_path, staged)
        os.chmod(staged, 0o644)  # readable by the cape user, still not executable
    except OSError as e:
        print(f"      [!] could not stage sample: {e}")
        return None

    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print(f"      [!] submission timed out")
        return None
    except Exception as e:
        print(f"      [!] submission failed: {e}")
        return None
    finally:
        # The staged copy is only needed until CAPE has ingested it.
        try:
            staged.unlink(missing_ok=True)
        except OSError:
            pass

    output = (result.stdout or "") + (result.stderr or "")
    match = TASK_ID_PATTERN.search(output)
    if match:
        return match.group(1)

    print(f"      [!] could not parse a task id from submit.py output:")
    for line in output.strip().splitlines()[-5:]:
        print(f"          {line}")
    return None


def reset_failed(manifest):
    """Return set-aside samples to the pending pool and clear their counters."""
    n = 0
    for row in manifest.values():
        if row.get("status") == "submit_failed":
            row["status"] = "pending"
            row["notes"] = strip_attempt_marker(row.get("notes", "")).strip(";")
            n += 1
    return n


def select_pending(manifest, count, order):
    """
    Choose which already-downloaded samples to submit next.

    Default order is round-robin across families rather than oldest-first.
    With an unbalanced download (say 1000 Cuba and 200 Babuk), oldest-first
    would send a whole batch of a single family, and family diversity is
    something this project needs in the results rather than in the archive.
    """
    pending = [row for row in manifest.values() if row.get("status") == "pending"]
    pending.sort(key=lambda r: r.get("added_date", ""))

    if order == "added":
        return pending[:count]

    by_family = defaultdict(list)
    for row in pending:
        by_family[row.get("family") or "(unknown)"].append(row)

    selected = []
    families = sorted(by_family)
    while len(selected) < count and any(by_family[f] for f in families):
        for family in families:
            if by_family[family] and len(selected) < count:
                selected.append(by_family[family].pop(0))
    return selected


def count_in_flight(manifest, analyses_dir=None):
    """
    How much work is actually still with CAPE.

    An earlier version counted manifest entries marked submitted with no
    verdict yet. That deadlocked: a verdict is only written when run_pipeline
    is run with --manifest, so during any period when the pipeline was not
    being run that way, the count grew without bound and topping up stopped
    entirely -- it reached 113 against a target of 20 while the sandbox sat
    idle.

    Completion is directly observable instead: CAPE writes
    <analyses_dir>/<task_id>/reports/report.json when an analysis finishes.
    An entry is in flight only while that file is absent, which is true both
    for queued tasks (no directory yet) and running ones.

    A finished analysis whose directory was later removed by the cleanup
    stage would look unfinished by that test, but cleanup only runs after the
    pipeline has recorded a result, so those entries are excluded first.
    """
    in_flight = 0
    for row in manifest.values():
        if row.get("status") != "submitted":
            continue
        if (row.get("result") or "").strip():
            continue          # already judged
        task_id = (row.get("cape_task_id") or "").strip()
        if not task_id:
            in_flight += 1    # submitted but no id recorded; assume pending
            continue
        if analyses_dir:
            report = Path(analyses_dir) / task_id / "reports" / "report.json"
            if report.exists():
                continue      # finished, whatever the manifest says
        in_flight += 1
    return in_flight


def run_submit_pending(args):
    """Submit samples already downloaded and recorded as pending."""
    manifest = load_manifest(args.manifest)
    if not manifest:
        print(f"[!] manifest is empty or missing: {args.manifest}")
        sys.exit(1)

    if args.retry_failed:
        n = reset_failed(manifest)
        save_manifest(args.manifest, manifest)
        print(f"Reset {n} previously failed samples back to pending\n")

    samples_dir = Path(args.samples_dir)

    # Keeping the queue at a target depth, rather than submitting everything,
    # means the machine never idles while analysis settings can still be
    # changed for whatever is submitted next.
    batch_size = args.submit_pending
    in_flight = count_in_flight(manifest, args.analyses_dir)
    if args.max_in_flight:
        room = args.max_in_flight - in_flight
        if room <= 0:
            print(f"Manifest: {args.manifest}")
            print(f"In flight: {in_flight} (target {args.max_in_flight}) -- "
                  f"queue is full, nothing submitted")
            return
        batch_size = min(batch_size, room)

    selected = select_pending(manifest, batch_size, args.order)

    total_pending = sum(1 for r in manifest.values() if r.get("status") == "pending")
    print(f"Manifest: {args.manifest} ({total_pending} pending, {in_flight} in flight)")
    print(f"Submitting: {len(selected)} (order: {args.order})")
    print(f"Settings: timeout={args.cape_timeout}"
          f"{' route=' + args.route if args.route else ''}"
          f"{' machine=' + args.machine if args.machine else ''}"
          f"{' enforce-timeout' if args.enforce_timeout else ''}")
    if args.dry_run:
        print("DRY RUN -- nothing will be submitted")
    print()

    by_family = defaultdict(int)
    for row in selected:
        by_family[row.get("family") or "(unknown)"] += 1
    print("   batch composition: " +
          ", ".join(f"{f}={n}" for f, n in sorted(by_family.items())) + "\n")

    submitted = failed = missing = 0
    for row in selected:
        sha = row["sha256"]
        sample_path = samples_dir / sha
        if not sample_path.exists():
            print(f"   [!] {sha[:16]}... file not found in {samples_dir}")
            missing += 1
            continue

        print(f"   - {sha[:16]}... {row.get('family', ''):<14} "
              f"{row.get('original_filename', '')[:30]}")

        task_id = submit_to_cape(
            sample_path, sha, args.cape_dir, args.poetry_bin, args.staging_dir,
            args.cape_timeout, args.machine, route=args.route,
            enforce_timeout=args.enforce_timeout, package=args.package,
            dry_run=args.dry_run)

        if args.dry_run:
            continue

        if task_id:
            manifest[sha]["status"] = "submitted"
            manifest[sha]["cape_task_id"] = task_id
            save_manifest(args.manifest, manifest)
            submitted += 1
            print(f"      -> task {task_id}")
        else:
            # Count attempts so a sample CAPE will never accept (corrupt file,
            # unsupported format) stops consuming a slot in every future batch,
            # while a transient failure such as a database lock still gets
            # retried.
            notes = manifest[sha].get("notes", "")
            attempts = count_submit_attempts(notes) + 1
            notes = strip_attempt_marker(notes) + f";submit_failed_x{attempts}"
            manifest[sha]["notes"] = notes.strip(";")

            if attempts >= MAX_SUBMIT_ATTEMPTS:
                manifest[sha]["status"] = "submit_failed"
                print(f"      [!] failed {attempts}x -- marked submit_failed, "
                      f"will not be retried")
            else:
                print(f"      [!] failed (attempt {attempts}/{MAX_SUBMIT_ATTEMPTS}), "
                      f"stays pending")
            save_manifest(args.manifest, manifest)
            failed += 1
        time.sleep(args.delay)

    print("\n" + "=" * 60)
    if args.dry_run:
        print(f"Would submit: {len(selected)}")
    else:
        print(f"Submitted:    {submitted}")
        if failed:
            print(f"Failed:       {failed}")
        if missing:
            print(f"Missing file: {missing}")
        set_aside = sum(1 for r in manifest.values() if r.get("status") == "submit_failed")
        if set_aside:
            print(f"Set aside:    {set_aside} (retry with --retry-failed)")
        still_pending = sum(1 for r in manifest.values() if r.get("status") == "pending")
        print(f"Still pending: {still_pending}")


def main():
    parser = argparse.ArgumentParser(
        description="Collect ransomware samples from MalwareBazaar with duplicate prevention.")
    parser.add_argument("--families", nargs="+", default=None,
                         help=f"Family signatures to query. Returns a family's full "
                              f"inventory. Default when neither --families nor --tags is "
                              f"given: {' '.join(SUGGESTED_FAMILIES)}")
    parser.add_argument("--tags", nargs="+", default=None,
                         help="Tags to query instead of, or as well as, families (e.g. "
                              "ransomware). Returns the most recent samples carrying the "
                              "tag across all families, so it finds families not named "
                              "explicitly. Capped at 1000 per tag by the API.")
    parser.add_argument("--limit", type=int, default=10,
                         help="Max samples to request per family (default: 10)")
    parser.add_argument("--samples-dir", default="./samples",
                         help="Directory to store downloaded samples (default: ./samples)")
    parser.add_argument("--manifest", default="manifest.csv",
                         help="Manifest CSV path (default: manifest.csv)")
    parser.add_argument("--also-known", nargs="+", default=None, metavar="CSV",
                         help="Additional manifests to treat as already collected. "
                              "Used when a second machine is collecting in parallel: "
                              "point each host at the other's manifest so neither "
                              "downloads what the other already has. Read only.")
    parser.add_argument("--file-type", default=None,
                         help="Only take samples whose file_type matches (e.g. exe)")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SAMPLE_BYTES,
                         metavar="BYTES",
                         help=f"Skip samples larger than this (default: "
                              f"{DEFAULT_MAX_SAMPLE_BYTES // 1_000_000}MB, matching "
                              f"max_sample_size in CAPE's web.conf). Pass 0 to disable.")
    parser.add_argument("--dry-run", action="store_true",
                         help="Query and report what would be downloaded, but download nothing")
    parser.add_argument("--delay", type=float, default=1.0,
                         help="Seconds to wait between downloads (be polite to the API)")
    parser.add_argument("--submit-pending", type=int, metavar="N", default=None,
                         help="Skip the API entirely: submit N samples already downloaded "
                              "and marked pending in the manifest. Lets downloading and "
                              "submitting be decoupled, so analysis settings can be changed "
                              "between batches instead of being fixed for a whole queue.")
    parser.add_argument("--analyses-dir", default=DEFAULT_CAPE_DIR + "/storage/analyses",
                         help="CAPE analyses directory, used to tell which submitted "
                              "analyses have actually finished")
    parser.add_argument("--max-in-flight", type=int, default=None, metavar="N",
                         help="With --submit-pending: submit only enough to bring the "
                              "number of outstanding analyses up to N. Intended for cron, "
                              "so the sandbox never sits idle while still submitting in "
                              "batches rather than flooding the queue in one go.")
    parser.add_argument("--retry-failed", action="store_true",
                         help="With --submit-pending: also retry samples previously set "
                              "aside after repeated submission failures, resetting their "
                              "attempt counter.")
    parser.add_argument("--order", choices=["balanced", "added"], default="balanced",
                         help="With --submit-pending: 'balanced' round-robins across "
                              "families so a batch is not dominated by whichever family "
                              "happened to have the most samples; 'added' is oldest-first.")
    parser.add_argument("--submit", action="store_true",
                         help="Submit each newly downloaded sample to CAPE and record "
                              "the returned task id in the manifest automatically")
    parser.add_argument("--cape-dir", default=DEFAULT_CAPE_DIR,
                         help=f"CAPE installation directory (default: {DEFAULT_CAPE_DIR})")
    parser.add_argument("--poetry-bin", default=DEFAULT_POETRY_BIN,
                         help=f"Absolute path to poetry (default: {DEFAULT_POETRY_BIN})")
    parser.add_argument("--staging-dir", default=DEFAULT_STAGING_DIR,
                         help=f"Directory CAPE can read samples from (default: {DEFAULT_STAGING_DIR})")
    parser.add_argument("--cape-timeout", type=int, default=300,
                         help="Analysis timeout in seconds passed to CAPE (default: 300)")
    parser.add_argument("--route", default="internet",
                         help="CAPE network route for the guest: none, inetsim, internet "
                              "(default: internet). Ransomware that waits on a C2 server "
                              "before encrypting will not trigger without network access, "
                              "which is why this defaults on -- but it does mean live "
                              "malware reaches the network, so use --route none or "
                              "--route inetsim when that is not acceptable.")
    parser.add_argument("--enforce-timeout", action="store_true",
                         help="Keep each analysis running for the full timeout even after "
                              "the sample exits. Catches payloads that start late, but since "
                              "most samples fail immediately it also multiplies total run "
                              "time -- roughly 3x fewer samples per day at a 10%% trigger rate.")
    parser.add_argument("--package", default=None,
                         help="CAPE analysis package (e.g. exe, dll). Left unset, CAPE "
                              "detects the type itself. Auto-detection is the safer default "
                              "here because MalwareBazaar's file_type is not always right: "
                              "a query filtered to file_type=exe returned an entry named "
                              "MFCLibrary7.dll, which forcing --package exe would mis-run.")
    parser.add_argument("--machine", default=None,
                         help="Specific CAPE machine to submit to (e.g. cuckoo1)")
    args = parser.parse_args()

    try:
        import requests
    except ImportError:
        print("[!] requests not installed (pip install requests)")
        sys.exit(1)

    # Submitting already-downloaded samples needs no API key.
    if args.submit_pending is not None:
        run_submit_pending(args)
        return

    if not args.families and not args.tags:
        args.families = SUGGESTED_FAMILIES

    auth_key = get_auth_key()
    samples_dir = Path(args.samples_dir)
    if not args.dry_run:
        samples_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest(args.manifest)

    # Hashes held by another machine, read but never written.
    #
    # Two hosts collecting into one shared manifest cannot work: both have
    # cron jobs rewriting it every half hour, and git cannot merge concurrent
    # edits to the same CSV rows without scrambling the sample history. So
    # each host owns its own manifest, and consults the other's only to avoid
    # downloading what has already been taken.
    external = {}
    for path in (args.also_known or []):
        other = load_manifest(path)
        external.update(other)
        print(f"Also known: {path} ({len(other)} hashes, read-only)")

    print(f"Manifest: {args.manifest} ({len(manifest)} known hashes"
          f"{f', {len(external)} more from elsewhere' if external else ''})")
    if args.families:
        print(f"Families: {', '.join(args.families)}")
    if args.tags:
        print(f"Tags:     {', '.join(args.tags)}")
    print(f"Limit per query: {args.limit}")
    if args.file_type:
        print(f"Filtering to file_type == {args.file_type}")
    if args.dry_run:
        print("DRY RUN -- nothing will be downloaded\n")
    else:
        print(f"Samples dir: {samples_dir.resolve()}\n")

    session = requests.Session()
    total_new = total_dupe = total_downloaded = total_failed = 0
    total_submitted = total_submit_failed = 0
    family_tally = defaultdict(int)
    # In dry-run mode nothing is written to the manifest, so a sample returned
    # by both a tag query and a family query would otherwise be reported as
    # new twice. Tracking it here keeps the projected totals honest.
    seen_this_run = set()

    # Each unit is (kind, value): a family signature or a tag.
    query_units = [("signature", f) for f in (args.families or [])]
    query_units += [("tag", t) for t in (args.tags or [])]

    for kind, value in query_units:
        label = f"tag:{value}" if kind == "tag" else value
        print(f"[{label}]")
        if kind == "tag":
            entries = query_tag(session, auth_key, value, args.limit)
        else:
            entries = query_family(session, auth_key, value, args.limit)
        if not entries:
            print("   (no results)\n")
            continue

        n_returned = len(entries)
        filtered_out = []
        if args.file_type:
            wanted = args.file_type.lower()
            kept = []
            for e in entries:
                if (e.get("file_type") or "").lower() == wanted:
                    kept.append(e)
                else:
                    filtered_out.append(e)
            entries = kept

        oversized = []
        if args.max_size:
            kept = []
            for e in entries:
                try:
                    size = int(e.get("file_size") or 0)
                except (TypeError, ValueError):
                    size = 0
                if size and size > args.max_size:
                    oversized.append((e, size))
                else:
                    kept.append(e)
            entries = kept

        new_entries, dupe_count = [], 0
        for entry in entries:
            sha = entry.get("sha256_hash")
            if not sha:
                continue
            if sha in manifest or sha in external or sha in seen_this_run:
                dupe_count += 1
            else:
                new_entries.append(entry)
                seen_this_run.add(sha)

        total_new += len(new_entries)
        total_dupe += dupe_count

        # Report the pre-filter count separately: otherwise "3 requested,
        # 2 returned" looks like the API ran short when in fact a sample was
        # dropped locally for having the wrong file type.
        line = f"   API returned {n_returned}"
        if args.file_type:
            line += f" | {len(entries)} match file_type={args.file_type}"
        line += f" | {len(new_entries)} new | {dupe_count} already known"
        print(line)

        if filtered_out:
            types = defaultdict(int)
            for e in filtered_out:
                types[e.get("file_type") or "(unknown)"] += 1
            detail = ", ".join(f"{t}={n}" for t, n in sorted(types.items()))
            print(f"   (skipped {len(filtered_out)} of other types: {detail})")

        if oversized:
            biggest = max(size for _e, size in oversized)
            print(f"   (skipped {len(oversized)} over {args.max_size / 1e6:.0f}MB, "
                  f"largest {biggest / 1e6:.1f}MB -- CAPE would reject these)")

        for entry in new_entries:
            sha = entry["sha256_hash"]
            fname = entry.get("file_name", "")
            ftype = entry.get("file_type", "")
            # For a signature query the family is the query term; for a tag
            # query it comes from the entry, or is left unknown.
            family = value if kind == "signature" else family_of(entry, "")
            shown = family or "(unattributed)"
            print(f"   - {sha[:16]}... {fname[:32]:<34} {shown[:16]:<18} type={ftype}")

            if args.dry_run:
                family_tally[family or "(unattributed)"] += 1
                continue

            zip_bytes = download_sample(session, auth_key, sha)
            if not zip_bytes:
                total_failed += 1
                continue

            out_path = extract_sample(zip_bytes, sha, samples_dir)
            if not out_path:
                total_failed += 1
                continue

            manifest[sha] = {
                "sha256": sha,
                "original_filename": fname,
                "family": family,
                "source": "malwarebazaar",
                "label": "ransomware",
                "added_date": now_iso(),
                "status": "pending",
                "cape_task_id": "",
                "result": "",
                "notes": f"file_type={ftype}",
            }
            save_manifest(args.manifest, manifest)
            total_downloaded += 1
            family_tally[family or "(unattributed)"] += 1
            print(f"      -> saved {out_path.name} and registered in manifest")

            if args.submit:
                task_id = submit_to_cape(
                    out_path, sha, args.cape_dir, args.poetry_bin,
                    args.staging_dir, args.cape_timeout, args.machine,
                    route=args.route, enforce_timeout=args.enforce_timeout,
                    package=args.package)
                if task_id:
                    manifest[sha]["status"] = "submitted"
                    manifest[sha]["cape_task_id"] = task_id
                    save_manifest(args.manifest, manifest)
                    total_submitted += 1
                    print(f"      -> submitted to CAPE as task {task_id}")
                else:
                    manifest[sha]["notes"] += ";submit_failed"
                    save_manifest(args.manifest, manifest)
                    total_submit_failed += 1

            time.sleep(args.delay)

        print()

    print("=" * 60)
    print(f"New samples found:  {total_new}")
    print(f"Already in manifest: {total_dupe}")
    if family_tally:
        print("\nFamily mix:")
        for fam, n in sorted(family_tally.items(), key=lambda x: -x[1]):
            print(f"   {fam:<24} {n}")
    if not args.dry_run:
        print(f"Downloaded:          {total_downloaded}")
        print(f"Failed:              {total_failed}")
        if args.submit:
            print(f"Submitted to CAPE:   {total_submitted}")
            if total_submit_failed:
                print(f"Submission failures: {total_submit_failed}")
            print(f"\nOnce CAPE finishes analysing, run the rest of the pipeline:")
            print(f"   python3 run_pipeline.py --analyses-dir {args.cape_dir}/storage/analyses \\")
            print(f"       --features-out ../../../data/features.csv \\")
            print(f"       --manifest {args.manifest}")
        else:
            print(f"\nSamples are downloaded but NOT submitted (pass --submit to automate).")
            print(f"   python3 manifest.py --manifest {args.manifest} list --status pending")


if __name__ == "__main__":
    main()
