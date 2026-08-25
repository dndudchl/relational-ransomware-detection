#!/usr/bin/env python3
"""
fetch_installers_github_search.py - Find Windows installers by searching GitHub,
rather than by naming projects from memory.

Why search rather than a list
-----------------------------
The hand-written list in fetch_installers_github_list.py runs out. Of 109 projects
named there, 26 gave nothing: they publish an AppImage, a deb or a zip, and no
amount of adding more names fixes that, because the failure is not that the
name was wrong. It is that whether a project ships a Windows installer is a
fact about the project that cannot be recalled reliably.

Searching inverts the problem. GitHub is asked for repositories in a topic,
each one's latest release is checked for an .exe, and the ones that have one
are kept. Nothing is guessed, so nothing 404s.

Why these topics
----------------
The held-out sample of real software is dominated by Sysinternals command
line tools, which read a little and write almost nothing. That makes the
measured false positive rate a statement about that kind of program. What is
missing is software that opens a folder's worth of files for an ordinary
reason -- which is the band where the detector actually struggles:

    files opened      flagged
    under 10          0.000
    10 to 49          0.000
    50 to 199         0.048
    200 or more       0.011

So the topics below are chosen for programs that walk a directory tree:
backup, synchronisation, archiving, media conversion, file management, disk
analysis, duplicate finding, encryption. An installer is a second reason --
installing writes hundreds of files, for a reason nobody would question.

Usage
-----
  export GITHUB_TOKEN=...
  python3 fetch_installers_github_search.py --out-list ~/work/repos_found.txt
  python3 fetch_installers_github_search.py --out-list ~/work/repos_found.txt \\
      --topics backup file-sync --min-stars 100 --per-topic 40
"""

import os
import re
import csv
import sys
import json
import time
import argparse
import urllib.parse
import urllib.request
import urllib.error

SEARCH = "https://api.github.com/search/repositories?q={q}&sort=stars&per_page={n}"
RELEASE = "https://api.github.com/repos/{repo}/releases/latest"
UA = "research-sample-collection"

# Categories the held-out set is thin on. Each is a program that opens many
# files as its ordinary business, which is the band the detector confuses
# with encryption.
TOPICS = [
    "backup",
    "file-sync",
    "file-synchronization",
    "file-manager",
    "archiver",
    "compression",
    "media-converter",
    "video-converter",
    "image-processing",
    "disk-usage",
    "duplicate-file-finder",
    "encryption",
    "file-encryption",
    "batch-processing",
    "file-transfer",
    "photo-manager",
    "music-player",
    "ebook",
    "pdf",
    "indexing",
    "search-engine",
    "text-editor",
    "ide",
    "screenshot",
    "download-manager",
]

INSTALLER = re.compile(r"(?i)\.(exe|msi)$")
SKIP = re.compile(r"(?i)(symbols|pdb|debug|portable|\.zip\.exe$|sha256|\.sig$|"
                  r"blockmap|\.asc$|checksum)")
WRONG_ARCH = re.compile(r"(?i)(arm64|aarch64|_arm\b|-arm\b|\.arm\.|"
                        r"linux|darwin|macos|osx|\.dmg|\.deb|\.rpm)")


def api(url, token, timeout=30):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/vnd.github+json",
        **({"Authorization": f"Bearer {token}"} if token else {}),
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def search_topic(topic, token, per_topic, min_stars):
    """Repositories in a topic, most starred first."""
    q = urllib.parse.quote(f"topic:{topic} stars:>={min_stars}")
    try:
        data = api(SEARCH.format(q=q, n=min(per_topic, 100)), token)
    except urllib.error.HTTPError as e:
        print(f"   {topic:<26}search failed: HTTP {e.code}")
        return []
    except Exception as e:
        print(f"   {topic:<26}search failed: {type(e).__name__}")
        return []
    return [item["full_name"] for item in data.get("items", [])]


def windows_installer(repo, token, max_mb):
    """
    The best Windows installer asset in the latest release, or None.

    "Best" means: an .exe or .msi, not a debug or portable build, not for an
    architecture the guest cannot run, and under the size cap. Where several
    qualify the largest is taken, since that is usually the full installer
    rather than a stub.
    """
    try:
        rel = api(RELEASE.format(repo=repo), token)
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, type(e).__name__

    best = None
    for a in rel.get("assets", []) or []:
        name = a.get("name", "")
        if not INSTALLER.search(name) or SKIP.search(name):
            continue
        if WRONG_ARCH.search(name):
            continue
        size = a.get("size", 0)
        if size > max_mb * 1e6 or size < 100_000:
            continue
        if best is None or size > best[2]:
            best = (name, a.get("browser_download_url"), size)
    if best is None:
        return None, rel.get("tag_name", "?")
    return best, rel.get("tag_name", "?")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    p.add_argument("--topics", nargs="*", default=TOPICS)
    p.add_argument("--per-topic", type=int, default=30,
                   help="Repositories to consider per topic")
    p.add_argument("--min-stars", type=int, default=100)
    p.add_argument("--max-mb", type=float, default=250)
    p.add_argument("--exclude",
                   help="File of owner/repo already collected, one per line")
    p.add_argument("--out-list", default="/tmp/repos_found.txt")
    p.add_argument("--out-csv", default="/tmp/repos_found.csv")
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after this many installers are found")
    args = p.parse_args()

    if not args.token:
        print("A token is needed: the search API allows 10 requests a minute")
        print("without one, and this makes hundreds of calls.")
        sys.exit(1)

    already = set()
    if args.exclude and os.path.exists(os.path.expanduser(args.exclude)):
        with open(os.path.expanduser(args.exclude)) as f:
            already = {ln.strip().lower() for ln in f if ln.strip()}
        print(f"excluding {len(already)} repositories already collected")

    # Gather candidates first, so the same repository appearing under two
    # topics is only checked once.
    candidates, seen_topic = [], {}
    for t in args.topics:
        found = search_topic(t, args.token, args.per_topic, args.min_stars)
        new = 0
        for repo in found:
            if repo.lower() in already or repo in seen_topic:
                continue
            seen_topic[repo] = t
            candidates.append(repo)
            new += 1
        print(f"   {t:<26}{len(found):>4} repos, {new:>4} new")
        time.sleep(2.0)          # the search API allows 30 requests a minute

    print(f"\n{len(candidates)} candidates; checking releases")

    rows, checked = [], 0
    for repo in candidates:
        best, tag = windows_installer(repo, args.token, args.max_mb)
        checked += 1
        if best:
            name, url, size = best
            rows.append({"repo": repo, "topic": seen_topic[repo],
                         "filename": name, "bytes": size,
                         "tag": tag, "url": url})
            print(f"   {len(rows):>3}  {size/1e6:>6.1f} MB  "
                  f"{seen_topic[repo][:14]:<16}{repo[:34]:<36}{name[:40]}")
            if args.limit and len(rows) >= args.limit:
                print(f"\nstopping at {args.limit}")
                break
        if checked % 25 == 0:
            print(f"      ... {checked}/{len(candidates)} checked, "
                  f"{len(rows)} found")
        time.sleep(0.15)

    out_list = os.path.expanduser(args.out_list)
    with open(out_list, "w") as f:
        for r in rows:
            f.write(r["repo"] + "\n")

    out_csv = os.path.expanduser(args.out_csv)
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["repo", "topic", "filename",
                                          "bytes", "tag", "url"])
        w.writeheader()
        w.writerows(rows)

    print(f"\n{len(rows)} repositories publish a Windows installer")
    by_topic = {}
    for r in rows:
        by_topic[r["topic"]] = by_topic.get(r["topic"], 0) + 1
    for t in sorted(by_topic, key=lambda x: -by_topic[x]):
        print(f"   {t:<26}{by_topic[t]:>4}")
    print(f"\n[saved] {out_list}")
    print(f"[saved] {out_csv}")
    print("\nFeed the list to fetch_installers_github_list.py:")
    print("   python3 fetch_installers_github_list.py --only-extra --max-mb 250 \\")
    print(f"       --outdir ~/installers --extra $(cat {args.out_list} | tr '\\n' ' ')")


if __name__ == "__main__":
    main()
