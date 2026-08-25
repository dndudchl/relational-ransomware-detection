#!/usr/bin/env python3
"""
build_shape_grid.py - Compile the designed variant set across three
toolchains.

The grid
--------
Ten shapes, each at a distinct point in the space the relational features
measure, crossed with five volumes and two traversal orders. Neighbouring
cells differ in one relation:

    B / C            same read and write counts, sets coincide or not
    D / J            same file operations, one encrypts
    D / K            same destruction, one writes a replacement
    sweep / random   same everything, only the order

The last pair is the reason the grid exists. Every count is identical --
same files, same operations, same number of calls -- so a model that
separates them is using a relation between events and one that does not,
is not. Nothing else in the study isolates that.

Three toolchains
----------------
mingw C, Go and Rust build the identical behaviour. The positive class is
not built one way either: Hive, Akira and BlackCat are Rust and account for
405 of the 1,849 encrypting runs. Go and Rust link statically and carry
their own runtime, so their import tables have nothing in common with a
mingw binary. If the three agree, the model is reading behaviour. If they
disagree, it is reading the compiler.

C carries the order axis on its own, since traversal order is decided by
this code rather than by the toolchain, and spending the Go and Rust budget
on repeating it would buy nothing.

Usage
-----
  python3 build_shape_grid.py --outdir ~/hn3 --plan main
  python3 build_shape_grid.py --outdir ~/hn3 --plan all --dry-run
"""

import os
import csv
import argparse
import subprocess
from collections import Counter

CC = "x86_64-w64-mingw32-gcc"

SHAPES = {
    1:  ("A", "read only",                          "read_not_write 1.0"),
    2:  ("B", "read, write the same path",           "rw_jaccard 1.0"),
    3:  ("C", "read, write elsewhere, keep",         "rw_jaccard 0.0, harmless"),
    4:  ("D", "read, write elsewhere, delete",       "chain_read_destroy, writes"),
    5:  ("E", "read, write the same path, delete",   "chain_full 1.0"),
    6:  ("F", "read many, write one",                "rw_size_ratio -> 0"),
    7:  ("K", "read, delete, no write",              "chain_read_destroy, no writes"),
    8:  ("H", "scratch files, written and removed",  "write_not_read, originals intact"),
    9:  ("I", "rename only",                         "moves only"),
    10: ("J", "read, encrypt, write, delete",        "D plus CryptEncrypt"),
}

# Which shapes leave what was already there untouched. Used to mark the
# manifest so that analysis can separate a detector being wrong from a
# detector being right, and so that only the harmless ones are ever
# considered for training.
CATEGORY = {
    1: "harmless", 3: "harmless", 8: "harmless",
    2: "ambiguous", 9: "ambiguous",
    4: "destroys", 5: "destroys", 6: "destroys",
    7: "destroys", 10: "destroys",
}

LIMITS = [50, 200, 500, 1000, 2000]
ORDERS = [0, 1]
TIMINGS = [0, 1, 2, 3]

# Shapes used where the grid is a subset: two harmless, one destroying, one
# that writes without reading. Enough spread to see an effect without
# repeating the whole grid.
SUBSET = [1, 3, 4, 8]


def plan_main():
    """The full plan: 1,002 binaries."""
    jobs = []

    # C: shapes x volumes x orders, six of each
    for sh in SHAPES:
        for lim in LIMITS:
            for order in ORDERS:
                for rep in range(6):
                    jobs.append(dict(tool="c", shape=sh, limit=lim,
                                     order=order, timing=0, effects=0,
                                     fake=0, rep=rep))

    # Go and Rust: shapes x volumes, twice each, sweep only
    for tool in ("go", "rust"):
        for sh in SHAPES:
            for lim in LIMITS:
                for rep in range(2):
                    jobs.append(dict(tool=tool, shape=sh, limit=lim,
                                     order=0, timing=0, effects=0,
                                     fake=0, rep=rep))

    # Timing: a subset of shapes at one volume, all four rhythms
    for sh in SUBSET:
        for t in TIMINGS:
            for rep in range(5):
                jobs.append(dict(tool="c", shape=sh, limit=200, order=0,
                                 timing=t, effects=0, fake=0, rep=rep))

    # Import table: the same subset with a ransomware-shaped import list
    for sh in SUBSET:
        for lim in LIMITS:
            for rep in range(2):
                jobs.append(dict(tool="c", shape=sh, limit=lim, order=0,
                                 timing=0, effects=0, fake=1, rep=rep))
    return jobs


def plan_order():
    """
    The order pair, rebuilt.

    The first run of this pair was not controlled: the shuffle happened
    before the list was cut to the limit, so the two orders processed
    different files and differed in call count by 18% as well as in
    sequence. With that fixed in hardneg_matrix.c, the pair is worth
    repeating on its own -- it is the only comparison in the grid where
    every count is identical, which makes it the only one whose outcome
    cannot be explained by volume.

    Ten shapes at three volumes, both orders, five repeats: 300 binaries,
    which is a few hours on two machines rather than the day the whole grid
    took.
    """
    jobs = []
    for sh in SHAPES:
        for lim in (200, 500, 2000):
            for order in ORDERS:
                for rep in range(5):
                    jobs.append(dict(tool="c", shape=sh, limit=lim,
                                     order=order, timing=0, effects=0,
                                     fake=0, rep=rep, group="order2"))
    return jobs


def plan_extra():
    """Held back until the main plan has run: C repeats six to nine."""
    jobs = []
    for sh in SHAPES:
        for lim in LIMITS:
            for order in ORDERS:
                for rep in range(6, 9):
                    jobs.append(dict(tool="c", shape=sh, limit=lim,
                                     order=order, timing=0, effects=0,
                                     fake=0, rep=rep))
    return jobs


def name_of(j):
    letter = SHAPES[j["shape"]][0]
    parts = [f"x{j['tool']}", letter, f"l{j['limit']}"]
    if j["order"]:
        parts.append("rand")
    if j["timing"]:
        parts.append(f"t{j['timing']}")
    if j["effects"]:
        parts.append(f"e{j['effects']}")
    if j["fake"]:
        parts.append("imp")
    parts.append(f"r{j['rep']}")
    return "_".join(parts)


def build_c(j, out, src):
    flags = [f"-DSHAPE={j['shape']}", f"-DLIMIT={j['limit']}",
             f"-DORDER={j['order']}", f"-DTIMING={j['timing']}",
             f"-DEFFECTS={j['effects']}", f"-DFAKE_IMPORTS={j['fake']}",
             f"-DBUILD_REP={j['rep']}"]
    # The fake-import build references networking, shell and service APIs
    # that live outside the default link set, so those libraries have to be
    # named. They are only linked for that build: adding them everywhere
    # would put the same imports in every variant and destroy the comparison
    # the flag exists to make.
    libs = ["-lwininet", "-lshell32", "-ladvapi32", "-lole32"] if j["fake"] else []
    cmd = [CC, "-O2"] + flags + ["-o", out, src] + libs
    return subprocess.run(cmd, capture_output=True, text=True)


def build_go(j, out, srcdir):
    # Parameters go in at link time so each variant is a distinct binary with
    # its own hash, matching how the C ones are built. Passing them as
    # arguments would give every variant the same file.
    ld = " ".join(f"-X main.{k}={v}" for k, v in
                  (("shape", j["shape"]), ("limit", j["limit"]),
                   ("order", j["order"]), ("timing", j["timing"]),
                   ("effects", j["effects"])))
    env = dict(os.environ, GOOS="windows", GOARCH="amd64", CGO_ENABLED="0")
    return subprocess.run(["go", "build", "-ldflags", ld, "-o", out, "."],
                          cwd=srcdir, capture_output=True, text=True, env=env)


def build_rust(j, out, srcdir):
    env = dict(os.environ,
               HN_SHAPE=str(j["shape"]), HN_LIMIT=str(j["limit"]),
               HN_ORDER=str(j["order"]), HN_TIMING=str(j["timing"]),
               HN_EFFECTS=str(j["effects"]))
    r = subprocess.run(["cargo", "build", "--release",
                        "--target", "x86_64-pc-windows-gnu"],
                       cwd=srcdir, capture_output=True, text=True, env=env)
    if r.returncode == 0:
        built = os.path.join(srcdir, "target", "x86_64-pc-windows-gnu",
                             "release", "hardneg.exe")
        if os.path.exists(built):
            subprocess.run(["cp", built, out])
        else:
            r.returncode = 1
            r.stderr += f"\nexpected {built}"
    return r


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", default="./hn3")
    parser.add_argument("--plan", choices=["main", "extra", "order", "all"],
                         default="main")
    parser.add_argument("--src", default=".",
                         help="Directory holding c/, go/ and rust/")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip", nargs="*", default=[],
                         choices=["c", "go", "rust"],
                         help="Toolchains to leave out, for when one is not "
                              "installed")
    args = parser.parse_args()

    jobs = []
    if args.plan in ("main", "all"):
        jobs += plan_main()
    if args.plan in ("extra", "all"):
        jobs += plan_extra()
    if args.plan == "order":
        jobs = plan_order()
    jobs = [j for j in jobs if j["tool"] not in args.skip]

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    src = os.path.expanduser(args.src)

    by_tool = Counter(j["tool"] for j in jobs)
    print(f"{len(jobs)} binaries: " +
          ", ".join(f"{k} {v}" for k, v in sorted(by_tool.items())))
    print()
    print("shape spread, C only:")
    c_jobs = [j for j in jobs if j["tool"] == "c"]
    for sh in SHAPES:
        n = sum(1 for j in c_jobs if j["shape"] == sh)
        letter, what, measures = SHAPES[sh]
        print(f"   {letter}  {n:>4}  {what:<38}{measures}")
    print()
    print(f"volumes  {dict(sorted(Counter(j['limit'] for j in jobs).items()))}")
    print(f"orders   {dict(sorted(Counter(j['order'] for j in jobs).items()))}")
    print(f"category {dict(Counter(CATEGORY[j['shape']] for j in jobs))}")

    if args.dry_run:
        print("\ndry run; nothing built")
        return

    rows, failed = [], []
    for n, j in enumerate(jobs, 1):
        name = name_of(j)
        out = os.path.join(outdir, name + ".exe")
        if j["tool"] == "c":
            r = build_c(j, out, os.path.join(src, "c", "hardneg_matrix.c"))
        elif j["tool"] == "go":
            r = build_go(j, out, os.path.join(src, "go"))
        else:
            r = build_rust(j, out, os.path.join(src, "rust"))

        if r.returncode:
            failed.append((name, (r.stderr or "").strip().splitlines()[:1]))
        else:
            letter, what, _ = SHAPES[j["shape"]]
            rows.append({"filename": name + ".exe", "tool": j["tool"],
                          "shape": letter, "shape_id": j["shape"],
                          "limit": j["limit"], "order": j["order"],
                          "timing": j["timing"], "effects": j["effects"],
                          "fake_imports": j["fake"], "rep": j["rep"],
                          "category": CATEGORY[j["shape"]],
                          "description": what})
        if n % 25 == 0 or n == len(jobs):
            print(f"\r   built {len(rows)}/{len(jobs)}", end="", flush=True)
    print()

    if failed:
        print(f"\n[!] {len(failed)} failed")
        for name, err in failed[:6]:
            print(f"    {name}: {err}")

    manifest = os.path.join(outdir, "shape_manifest.csv")
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"\n{len(rows)} executables in {outdir}")
    print(f"[saved] {manifest}")
    print("\nEach is a distinct binary with its own hash, so the feature")
    print("table gets one row per variant rather than one row repeated.")
    print("The manifest carries the parameters, which is what lets the")
    print("analysis fold the results along one axis at a time.")


if __name__ == "__main__":
    main()
