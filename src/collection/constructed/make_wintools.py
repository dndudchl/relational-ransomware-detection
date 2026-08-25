#!/usr/bin/env python3
"""
make_wintools.py - Hard negatives that are Windows itself.

Why these and not more variants
-------------------------------
The false positive rate falls as more kinds of active benign software go into
training -- 0.794 with none, 0.535 with 96 kinds, 0.372 with 134, 0.245 with
163. The limit is kinds, not copies, and the constructed grid has run out of
them: ten shapes by two orders by three toolchains is sixty, and everything
else is the same program at another size.

What it has not run out of is real software. Of the hard negatives that open
fifty files or more, thirty-five are signed programs somebody else wrote, and
thirty-four of those are classified as ransomware. That is the worst result
in the set and the smallest sample in it.

Windows ships with tools that move, copy, rename and delete files in bulk.
They are signed by Microsoft, present on every installation, and an
administrator uses them daily. `robocopy /MIR` in particular reads a tree,
writes a copy of it, and deletes whatever is in the destination that is not
in the source -- which is reading, writing and deleting across hundreds of
files, for a reason nobody would question.

They are also reproducible in a way downloaded installers are not: anyone
repeating this has the same binaries, at the same versions, without fetching
anything.

Verify before generating everything
-----------------------------------
Not all of these exist on every build. `tar` and `curl` arrived in Windows 10
1803; `cipher` and `compact` exist everywhere but do their work in the kernel
where the sandbox records nothing, which is already documented as a blind
spot. Run with --probe first, submit those five, and generate the rest once
they come back with something in them.

Usage
-----
  python3 make_wintools.py --probe --outdir ~/wintools
  python3 make_wintools.py --outdir ~/wintools
"""

import os
import csv
import argparse

# Where the tools work. Kept to the same roots the compiled grid walks, so a
# batch file and a variant of the same shape can be compared.
SRC_DOCS = r"%USERPROFILE%\Documents"
SRC_DESK = r"%USERPROFILE%\Desktop"
SRC_PROF = r"%USERPROFILE%"
SRC_PROG = r"C:\Program Files"
DST = r"%TEMP%\wt_out"

HEADER = ("@echo off\r\n"
          "rem A Windows built-in tool doing what it is for.\r\n"
          "setlocal enabledelayedexpansion\r\n")


def task(body, note=""):
    lines = HEADER
    if note:
        lines += f"rem {note}\r\n"
    lines += body.replace("\n", "\r\n")
    return lines + "\r\necho finished\r\n"


# The five to try first. One of each mechanism, so a failure says which
# mechanism failed rather than leaving forty files to sort through.
PROBE = {
    "robocopy_mirror": (
        "robocopy mirrors Documents into a scratch folder",
        f'md "{DST}" 2>nul\n'
        f'robocopy "{SRC_DOCS}" "{DST}" /MIR /R:0 /W:0 /NFL /NDL /NJH /NJS\n'
        'echo robocopy exit !errorlevel!'),
    "xcopy_tree": (
        "xcopy copies the profile tree",
        f'md "{DST}" 2>nul\n'
        f'xcopy "{SRC_DOCS}" "{DST}" /E /H /Y /Q /C\n'
        'echo xcopy exit !errorlevel!'),
    "attrib_recursive": (
        "attrib walks the profile setting and clearing a flag",
        f'attrib +A /S /D "{SRC_PROF}\\*" > nul 2>&1\n'
        f'attrib -A /S /D "{SRC_PROF}\\*" > nul 2>&1\n'
        'echo attrib done'),
    "forfiles_touch": (
        "forfiles opens every document it finds",
        # Inside /C the redirection has to be written as its hex code, or
        # the outer shell consumes it and forfiles is handed a broken command.
        f'forfiles /P "{SRC_DOCS}" /S /M *.* /C "cmd /c type @path 0x3E nul" '
        '> nul 2>&1\necho forfiles exit !errorlevel!'),
    "certutil_hash": (
        "certutil hashes every file in the profile",
        f'for /r "{SRC_DOCS}" %%f in (*) do @certutil -hashfile "%%f" SHA256 '
        '> nul 2>&1\necho hashed'),
}

# The rest, generated once the probe comes back with activity in it.
TASKS = {
    # --- copying, in the several ways Windows offers ---
    "robocopy_mirror_desktop": (
        "robocopy mirrors the Desktop",
        f'md "{DST}" 2>nul\nrobocopy "{SRC_DESK}" "{DST}" /MIR /R:0 /W:0 /NJH /NJS'),
    "robocopy_move": (
        "robocopy moves a scratch tree it made itself, deleting the source",
        # /MOVE deletes what it copies. Pointed at Documents it would take
        # the sandbox agent with it and end the analysis, so it is given a
        # tree of its own to move: the mechanism is the same and nothing that
        # was already there is touched.
        f'md "{DST}\\src" 2>nul\n'
        f'for /l %%i in (1,1,400) do @echo x > "{DST}\\src\\f%%i.dat"\n'
        f'robocopy "{DST}\\src" "{DST}\\dst" /MOVE /E /R:0 /W:0 /NJH /NJS'),
    "robocopy_purge": (
        "robocopy copies, then purges what is no longer in the source",
        f'md "{DST}" 2>nul\n'
        f'robocopy "{SRC_DOCS}" "{DST}" /E /R:0 /W:0 /NJH /NJS\n'
        f'robocopy "{SRC_DESK}" "{DST}" /PURGE /R:0 /W:0 /NJH /NJS'),
    "robocopy_progfiles": (
        "robocopy reads Program Files without writing anything",
        f'robocopy "{SRC_PROG}" "{DST}" /E /L /R:0 /W:0 /NJH /NJS'),
    "xcopy_desktop": (
        "xcopy copies the Desktop",
        f'md "{DST}" 2>nul\nxcopy "{SRC_DESK}" "{DST}" /E /H /Y /Q /C'),
    "copy_loop": (
        "a plain copy loop over the profile",
        f'md "{DST}" 2>nul\n'
        f'for /r "{SRC_DOCS}" %%f in (*) do @copy /y "%%f" "{DST}\\" > nul 2>&1'),

    # --- renaming and moving in place ---
    "ren_extension": (
        "a bulk rename onto a shared extension, then back",
        # The sandbox agent is a .pyw under Documents. Renaming it does not
        # stop the running process but does stop the next analysis finding
        # it, so it is skipped here as everywhere else.
        f'for /r "{SRC_DOCS}" %%f in (*) do @(if /i not "%%~xf"==".pyw" '
        'if /i not "%%~xf"==".py" ren "%%f" "%%~nxf.bak") > nul 2>&1\n'
        f'for /r "{SRC_DOCS}" %%f in (*.bak) do @ren "%%f" "%%~nf" > nul 2>&1'),
    "move_and_back": (
        "move the Desktop's contents out and back",
        # The Desktop rather than Documents, because the agent is not there.
        f'md "{DST}" 2>nul\n'
        f'move /y "{SRC_DESK}\\*" "{DST}" > nul 2>&1\n'
        f'move /y "{DST}\\*" "{SRC_DESK}" > nul 2>&1'),

    # --- reading everything ---
    "certutil_hash_profile": (
        "certutil hashes the whole profile",
        f'for /r "{SRC_PROF}" %%f in (*) do @certutil -hashfile "%%f" MD5 '
        '> nul 2>&1'),
    "findstr_recursive": (
        "findstr reads every file looking for a string",
        f'findstr /s /i /m "invoice" "{SRC_PROF}\\*" > nul 2>&1'),
    "type_all": (
        "type reads every document",
        f'for /r "{SRC_DOCS}" %%f in (*) do @type "%%f" > nul 2>&1'),
    "fc_compare": (
        "fc compares each file against a copy of itself",
        f'md "{DST}" 2>nul\n'
        f'xcopy "{SRC_DESK}" "{DST}" /E /H /Y /Q /C > nul 2>&1\n'
        f'for /r "{SRC_DESK}" %%f in (*) do @fc "%%f" "{DST}\\%%~nxf" > nul 2>&1'),

    # --- metadata across a tree, touching every file without reading it ---
    "takeown_profile": (
        "takeown claims ownership of every file in the profile",
        f'takeown /f "{SRC_PROF}" /r /d y > nul 2>&1'),
    "icacls_grant": (
        "icacls rewrites permissions across the profile",
        f'icacls "{SRC_PROF}" /grant "%USERNAME%":(OI)(CI)F /t /q > nul 2>&1'),
    "attrib_hidden": (
        "attrib hides and unhides everything",
        f'attrib +H /S /D "{SRC_DESK}\\*" > nul 2>&1\n'
        f'attrib -H /S /D "{SRC_DESK}\\*" > nul 2>&1'),
    "dir_recursive": (
        "dir enumerates the whole disk",
        'dir C:\\ /s /b > nul 2>&1'),

    # --- deleting things it made itself ---
    "scratch_churn": (
        "make a thousand files and delete them, the way a build does",
        f'md "{DST}" 2>nul\n'
        f'for /l %%i in (1,1,1000) do @echo scratch > "{DST}\\f%%i.tmp"\n'
        f'del /q "{DST}\\*.tmp" > nul 2>&1'),
    "scratch_beside": (
        "write a temporary file beside each document and remove it",
        f'for /r "{SRC_DOCS}" %%f in (*) do @(echo tmp > "%%f.tmp" '
        '& del /q "%%f.tmp") > nul 2>&1'),

    # --- archiving with what Windows provides ---
    "tar_archive": (
        "tar, present since Windows 10 1803, archives the Desktop",
        f'md "{DST}" 2>nul\ntar -cf "{DST}\\desk.tar" -C "{SRC_DESK}" . '
        '> nul 2>&1\necho tar exit !errorlevel!'),
    "compress_archive": (
        "PowerShell's Compress-Archive over Documents",
        'powershell -NoProfile -Command '
        f'"Compress-Archive -Path \'{SRC_DOCS}\\*\' '
        f'-DestinationPath \'{DST}\\docs.zip\' -Force" > nul 2>&1'),

    # --- the two that are known to be invisible, kept as controls ---
    "cipher_encrypt": (
        "cipher /e, which encrypts in the kernel where nothing is recorded",
        f'cipher /e /s:"{SRC_DESK}" > nul 2>&1'),
    "compact_compress": (
        "compact /c, invisible for the same reason",
        f'compact /c /s:"{SRC_DESK}" /i /q > nul 2>&1'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", default="./wintools")
    parser.add_argument("--probe", action="store_true",
                         help="Generate only the five that test each "
                              "mechanism, to submit before the rest")
    args = parser.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    chosen = PROBE if args.probe else {**PROBE, **TASKS}
    rows = []
    for name, (note, body) in chosen.items():
        fn = f"w_{name}.bat"
        path = os.path.join(outdir, fn)
        with open(path, "w", newline="") as f:
            f.write(task(body, note))
        # Most of these leave what was there untouched. Three do not fit
        # that description and are marked accordingly, because calling
        # everything harmless would make the category useless: takeown and
        # icacls rewrite the ownership and permissions of every file they
        # reach, and the rename walks every name in the folder before putting
        # them back.
        AMBIGUOUS = {"takeown_profile", "icacls_grant", "ren_extension",
                     "move_and_back", "robocopy_move", "cipher_encrypt",
                     "compact_compress"}
        rows.append({"filename": fn, "tool": name.split("_")[0],
                      "category": "ambiguous" if name in AMBIGUOUS else "harmless",
                      "description": note,
                      "bytes": os.path.getsize(path)})

    manifest = os.path.join(outdir, "wintools_manifest.csv")
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "tool", "category",
                                           "description", "bytes"])
        w.writeheader(); w.writerows(rows)

    print(f"{len(rows)} batch files in {outdir}")
    for r in rows:
        print(f"   {r['filename']:<32}{r['description']}")
    print(f"[saved] {manifest}")

    if args.probe:
        print("\nSubmit these five first. Each exercises a different")
        print("mechanism, so a failure says which one is unavailable on this")
        print("guest rather than leaving forty files to sort through.")
    else:
        from collections import Counter
        print()
        print("categories:", dict(Counter(r["category"] for r in rows)))
        print()
        print("The harmless ones leave what was there untouched. The seven")
        print("marked ambiguous rewrite ownership, permissions or names, or")
        print("move files and put them back -- defensible operations that")
        print("leave the same trail as an attack, which is the point of")
        print("having the category. cipher and compact are among them and")
        print("are known to leave no trace at all; a run with nothing in it")
        print("confirms the blind spot rather than being a failed sample.")


if __name__ == "__main__":
    main()
