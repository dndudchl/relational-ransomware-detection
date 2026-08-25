#!/usr/bin/env python3
"""
make_scripts.py - Generate benign scripts that manipulate files.

Why scripts, when the matrix already covers the behaviours
----------------------------------------------------------
Every hard negative so far is a C binary compiled by the same toolchain, run
as a single process. That makes them uniform in ways the experiment did not
intend: around sixty imports each against a hundred or more for the
ransomware, the same compiler artefacts throughout, and one process in the
tree.

A script has none of that. The sample the sandbox records is powershell.exe
or wscript.exe or cmd.exe -- signed by Microsoft, with an import table that
says nothing whatever about what the script does. The file work happens in a
process the static features cannot see into, and it happens through the
interpreter's own API usage rather than direct calls.

That separates two things the C variants confound. If a variant that copies
and deletes every document is detected, is it because of the file operations
or because of what the binary looked like? The same operations written in
PowerShell answer that: the binary is now powershell.exe, and it is the same
powershell.exe for the script that only reads.

There is a second reason. Administrators automate exactly this. A backup
script, a bulk rename, a cleanup of old temporary files -- these are written
in PowerShell and scheduled, and if a detector fires on them it fires on
routine operations work.

What is generated
-----------------
Four languages against five methods against three scopes and three volumes,
which is the same factorial the C matrix uses, so the two sets can be
compared directly.

Nothing here is obfuscated or evasive. Every script is readable and does
what it says.

Usage
-----
  python3 make_scripts.py --count 60 --outdir ~/scripts
"""

import os
import csv
import random
import argparse
from collections import Counter

# The CAPE agent lives in the user's Documents folder, as a .pyw that the
# guest starts at boot. A script that copies and deletes everything under
# Documents deletes it too, the agent stops answering, and the analysis is
# recorded as a guest timeout -- the sample looks like it failed rather than
# like it did something.
#
# Every generator here skips the interpreter's own file types. That costs
# nothing: the decoy set is documents, images and spreadsheets, and there is
# no .py or .pyw among them to be missed.
PROTECTED_EXT = ("pyw", "py")

# %LOCALAPPDATA%\Temp is where CAPE stages the analyser and the sample it is
# running. A recursive delete under LOCALAPPDATA walks into it and removes
# the machinery doing the observing, which ends the analysis the same way
# deleting the agent does -- and shows up in the results as a sample that
# failed rather than one that interfered with the instrument.
#
# The simplest guard that works in all four languages is to skip any path
# with \Temp\ in it, which also spares the ordinary temporary files no
# ransomware sample would count as a victim anyway.
PROTECTED_DIR = "Temp"

# One target, matching what the compiled grid walks, so a script and a C
# variant of the same shape and volume can be compared directly. Varying the
# scope here as well would mean a difference between them could be the
# language or could be the directory, and neither could be ruled out.
#
# The profile covers Documents, Desktop, Downloads and AppData in one walk,
# which is where the compiled variants find most of their files too.
SCOPES = {
    "profile": (r"$env:USERPROFILE", r"%USERPROFILE%"),
}

# The same four shapes the compiled grid uses, under the same names, so the
# two sets line up cell for cell.
#
#   A  read only                      read_not_write 1.0
#   C  read, write elsewhere, keep    rw_jaccard 0.0, nothing destroyed
#   D  read, write elsewhere, delete  chain_read_destroy, writes
#   K  read, delete, no write         chain_read_destroy, no writes
#
# D and K are the pair worth watching: identical destruction, and one writes
# a replacement while the other does not. Whether that changes anything is a
# question about relations rather than counts.
#
# Rename and scratch were dropped. Both are in the compiled grid as shapes I
# and H, and repeating them here would spend the budget on shapes that
# already have 60 and 90 variants rather than on the language comparison
# these scripts exist for.
METHODS = {
    "A": "read every file, change nothing",
    "C": "write a copy beside each, originals kept",
    "D": "write a copy, then remove the original",
    "K": "read each file, then remove it, writing nothing",
}

# Matching the compiled grid's lower three steps. The larger ones are left
# to the compiled variants: PowerShell was measured taking the whole
# ten-minute window to process 85 files, so a script asked for a thousand
# would be cut off, and a variant that did less is not a variant that
# behaved differently.
LIMITS = [50, 200, 0]     # 0 means no limit


# ---------------------------------------------------------------- PowerShell

def ps1(method, scope, limit):
    root = SCOPES[scope][0]
    take = f"| Select-Object -First {limit} " if limit else ""
    skip = " ".join(f"-and $_.Extension -ne '.{e}'" for e in PROTECTED_EXT)
    skip += r" -and $_.FullName -notlike '*\Temp\*'"
    head = f'''# Routine file maintenance.
$root = "{root}"
$files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {{ $true {skip} }} {take}
Write-Host "found $($files.Count) files under $root"
'''
    body = {
        "A": '''
foreach ($f in $files) {
    try { [System.IO.File]::ReadAllBytes($f.FullName) | Out-Null } catch { }
}
Write-Host "read complete"
''',
        "C": '''
foreach ($f in $files) {
    try { Copy-Item $f.FullName "$($f.FullName).matrix" -ErrorAction Stop } catch { }
}
Write-Host "copies written"
''',
        "D": '''
foreach ($f in $files) {
    try {
        Copy-Item $f.FullName "$($f.FullName).matrix" -ErrorAction Stop
        Remove-Item $f.FullName -Force -ErrorAction Stop
    } catch { }
}
Write-Host "archived and removed"
''',
        "K": '''
# Read, then remove, writing no replacement. The pair to D.
foreach ($f in $files) {
    try {
        [System.IO.File]::ReadAllBytes($f.FullName) | Out-Null
        Remove-Item $f.FullName -Force -ErrorAction Stop
    } catch { }
}
Write-Host "read and removed"
''',
    }[method]
    return head + body


# ---------------------------------------------------------------------- VBS

def vbs(method, scope, limit):
    root = SCOPES[scope][1]
    cap = f"    If n >= {limit} Then Exit Sub" if limit else ""
    action = {
        "A": '''      On Error Resume Next
      Set st = fso.OpenTextFile(f.Path, 1, False)
      junk = st.ReadAll
      st.Close
      On Error GoTo 0''',
        "C": '''      On Error Resume Next
      fso.CopyFile f.Path, f.Path & ".matrix"
      On Error GoTo 0''',
        "D": '''      On Error Resume Next
      fso.CopyFile f.Path, f.Path & ".matrix"
      fso.DeleteFile f.Path, True
      On Error GoTo 0''',
        "K": '''      On Error Resume Next
      Set st = fso.OpenTextFile(f.Path, 1, False)
      junk = st.ReadAll
      st.Close
      fso.DeleteFile f.Path, True
      On Error GoTo 0''',
    }[method]
    return rf''' ' Routine file maintenance.
Dim fso, n
Set fso = CreateObject("Scripting.FileSystemObject")
n = 0

Sub Walk(path)
  Dim folder, f, sub_
  On Error Resume Next
  Set folder = fso.GetFolder(path)
  If Err.Number <> 0 Then Exit Sub
  On Error GoTo 0
  For Each f In folder.Files
    If InStr(1, f.Name, ".pyw", 1) > 0 Or InStr(1, f.Name, ".py", 1) > 0 _
       Or InStr(1, f.Path, "\\Temp\\", 1) > 0 Then
      ' leave the sandbox agent alone
    Else
{cap}
{action}
    n = n + 1
    End If
  Next
  For Each sub_ In folder.SubFolders
    Walk sub_.Path
  Next
End Sub

Walk fso.GetAbsolutePathName(CreateObject("WScript.Shell").ExpandEnvironmentStrings("{root}"))
WScript.Echo "processed " & n & " files"
'''


# ---------------------------------------------------------------------- Batch

def bat(method, scope, limit):
    root = SCOPES[scope][1]
    action = {
        "A": 'type "%%f" > nul 2>&1',
        "C": 'copy /y "%%f" "%%f.matrix" > nul 2>&1',
        "D": 'copy /y "%%f" "%%f.matrix" > nul 2>&1 && del /f /q "%%f" > nul 2>&1',
        "K": 'type "%%f" > nul 2>&1 && del /f /q "%%f" > nul 2>&1',
    }[method]
    # A goto out of a parenthesised for body does not reliably stop the
    # loop in cmd, so the limit is enforced by guarding the work instead:
    # the loop still walks every path but stops acting after the cap.
    guard = (f"  if !n! lss {limit} ({action}& set /a n+=1)"
             if limit else f"  {action}& set /a n+=1")
    return rf'''@echo off
rem Routine file maintenance.
setlocal enabledelayedexpansion
set n=0
for /r "{root}" %%f in (*) do (
  set "P=%%~dpf"
  if /i not "%%~xf"==".pyw" if /i not "%%~xf"==".py" if "!P:\Temp\=!"=="!P!" (
{guard}
  )
)
echo processed !n! files
'''


# ------------------------------------------------------------------------ JS

def js(method, scope, limit):
    root = SCOPES[scope][1]
    action = {
        "A": '''      try { var st = fso.OpenTextFile(f.Path, 1, false); st.ReadAll(); st.Close(); }
      catch (e) { }''',
        "C": '''      try { fso.CopyFile(f.Path, f.Path + ".matrix"); } catch (e) { }''',
        "D": '''      try { fso.CopyFile(f.Path, f.Path + ".matrix");
                   fso.DeleteFile(f.Path, true); } catch (e) { }''',
        "K": '''      try { var st = fso.OpenTextFile(f.Path, 1, false); st.ReadAll(); st.Close();
                   fso.DeleteFile(f.Path, true); } catch (e) { }''',
    }[method]
    cap = f"      if (n >= {limit}) return;" if limit else ""
    return f'''// Routine file maintenance.
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var n = 0;

function walk(path) {{
  var folder;
  try {{ folder = fso.GetFolder(path); }} catch (e) {{ return; }}
  var it = new Enumerator(folder.files);
  for (; !it.atEnd(); it.moveNext()) {{
    var f = it.item();
    // Leave the agent and the analyser's staging directory alone.
    if (/\\.pyw?$/i.test(f.Name)) continue;
    if (f.Path.toLowerCase().indexOf("\\\\temp\\\\") >= 0) continue;
{cap}
{action}
    n++;
  }}
  var sub = new Enumerator(folder.SubFolders);
  for (; !sub.atEnd(); sub.moveNext()) walk(sub.item().Path);
}}

walk(shell.ExpandEnvironmentStrings("{root}"));
WScript.Echo("processed " + n + " files");
'''


LANGUAGES = {"ps1": ps1, "vbs": vbs, "bat": bat, "js": js}


# --------------------------------------------------- installed applications
#
# The guest has 7-Zip, Chrome, Acrobat and Office on it, put there when the
# image was built. They appeared in the ransomware analyses constantly --
# 7-Zip in 681 of them and Adobe in 694 -- because families walk into
# C:\Program Files and destroy what they find there.
#
# Running them on purpose is a different kind of negative from anything else
# in the set. The binary is signed, it was installed before this project
# started, and the operation is one a person asks for. 7-Zip with -mhe and
# -sdel in particular reads every document, writes an encrypted container
# and removes the originals, which is the same trail as encryption with the
# consent left out.
#
# Each path is tried in both its 64- and 32-bit locations, since the batch
# will run on whichever the guest happens to have.

SEVENZIP = [r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe"]
CHROME = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
          r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]
ACROBAT = [r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
           r"C:\Program Files\Adobe\Acrobat DC\Acrobat\x86\Acrobat\Acrobat.exe"]
WINWORD = [r"C:\Program Files (x86)\Microsoft Office\Office14\WINWORD.EXE"]
EXCEL = [r"C:\Program Files (x86)\Microsoft Office\Office14\EXCEL.EXE"]
# Installed for the user rather than system-wide, which is why it never
# appeared in the ransomware reports: those walk Program Files. It is on
# PATH regardless, so the bare name is kept as a fallback.
PYTHON = [r"C:\Users\admin\AppData\Local\Programs\Python\Python310-32\python.exe",
          "python.exe"]


def _try_paths(candidates, args, label):
    """Run whichever of the candidate paths exists."""
    lines = [f'echo {label}']
    for i, exe in enumerate(candidates):
        guard = "if exist" if i == 0 else "if not defined RAN if exist"
        lines.append(f'{guard} "{exe}" (set RAN=1& "{exe}" {args})')
    lines.append('if not defined RAN echo application not found')
    return "\n".join(lines)


# Each task is generated once per scope, the same way the matrix varies
# scope for the compiled variants. A 7-Zip archive of Documents and one of
# the whole profile are different amounts of work on different files, and
# which of them trips the detector is the question.
APP_SCOPES = {
    "desktop":   r"%USERPROFILE%\\Desktop",
    "documents": r"%USERPROFILE%\\Documents",
    "downloads": r"%USERPROFILE%\\Downloads",
    "profile":   r"%USERPROFILE%",
}


def _sevenzip(args, label):
    return _try_paths(SEVENZIP, args, label)


APP_TASKS = {
    "7z_encrypt_delete": (
        "7-Zip: encrypted archive, originals deleted",
        lambda root: _sevenzip(
            f'a -parchive2026 -mhe=on -y -sdel '
            f'"%TEMP%\\docs.7z" "{root}\\*" -xr!*.pyw -xr!*.py -xr!Temp',
            "7z encrypted archive with source deletion")),
    "7z_encrypt_keep": (
        "7-Zip: the same, originals kept",
        lambda root: _sevenzip(
            f'a -parchive2026 -mhe=on -y '
            f'"%TEMP%\\docs.7z" "{root}\\*" -xr!*.pyw -xr!*.py -xr!Temp',
            "7z encrypted archive, sources kept")),
    "7z_perfile": (
        "7-Zip: one container per file, original deleted",
        lambda root: 'echo per-file archiving\n'
                     f'for /r "{root}" %%f in (*) do (\n'
                     '  if /i not "%%~xf"==".pyw" if /i not "%%~xf"==".py" if "%%~dpf"=="%%~dpf" (\n'
                     f'    if exist "{SEVENZIP[0]}" "{SEVENZIP[0]}" '
                     'a -parchive2026 -mhe=on -mx0 -y -sdel "%%f.7z" "%%f" > nul 2>&1\n'
                     '  )\n)\necho done'),
    "7z_extract": (
        "7-Zip: pack, then unpack what it packed",
        lambda root: _sevenzip(f'a -y "%TEMP%\\bundle.7z" "{root}\\*"', "pack")
                     + "\n" + _sevenzip(
                         r'x -y -o"%TEMP%\unpacked" "%TEMP%\bundle.7z"', "unpack")),
    "python_copy_delete": (
        "Python copies each file then removes the original",
        lambda root: _python_task(_py_walk(root, """\
        try:
            shutil.copy2(src, src + '.archived')
            os.remove(src)
            n += 1
        except OSError:
            pass"""), imports="import os, shutil")),
    "python_read_only": (
        "Python reads every file and changes nothing",
        lambda root: _python_task(_py_walk(root, """\
        try:
            with open(src, 'rb') as fh:
                fh.read()
            n += 1
        except OSError:
            pass"""), imports="import os")),
    "python_scratch": (
        "Python writes temporary copies and removes them",
        lambda root: _python_task(_py_walk(root, """\
        tmp = src + '.tmp'
        try:
            shutil.copy2(src, tmp)
            os.remove(tmp)
            n += 1
        except OSError:
            pass"""), imports="import os, shutil")),
    "chrome_local": (
        "Chrome headless renders local files",
        lambda root, n=None: _try_paths(CHROME,
            f'--headless --disable-gpu --no-sandbox --dump-dom "file:///{root}"',
            "chrome headless")),
    "acrobat_open": (
        "Acrobat opens PDFs found here, then is closed",
        lambda root, n=6: 'echo opening pdfs\nset N=0\n'
                     f'for /r "{root}" %%f in (*.pdf) do (\n'
                     f'  if !N! lss {n} (start "" "%%f"& set /a N+=1& timeout /t 6 > nul)\n'
                     ')\ntimeout /t 20 > nul\n'
                     'taskkill /f /im Acrobat.exe /im AcroRd32.exe /im AcroCEF.exe > nul 2>&1\n'
                     'echo closed'),
    "office_open": (
        "Word and Excel open documents found here, then are closed",
        lambda root, n=8: 'echo opening office documents\nset N=0\n'
                     f'for /r "{root}" %%f in (*.docx *.xlsx) do (\n'
                     f'  if !N! lss {n} (start "" "%%f"& set /a N+=1& timeout /t 5 > nul)\n'
                     ')\ntimeout /t 25 > nul\n'
                     'taskkill /f /im WINWORD.EXE /im EXCEL.EXE > nul 2>&1\necho closed'),
}


def _py_walk(root, action):
    """
    A walk over one directory tree with the action applied to each file.

    The agent's own file types are skipped here as everywhere else: it lives
    in Documents, and a script that deletes what it finds there ends the
    analysis rather than being analysed.
    """
    # The scope constants carry doubled backslashes so they survive being
    # written into a batch file; a raw Python string needs them single, or
    # os.walk is handed a path that does not exist and silently finds
    # nothing -- a script that reports "processed 0" and looks like a
    # detection success when it is a generation bug.
    root = root.replace("\\\\", "\\")
    return (f"root = os.path.expandvars(r'{root}')\n"
            "n = 0\n"
            "for d, _, fs in os.walk(root):\n"
            "    for name in fs:\n"
            "        if name.lower().endswith(('.pyw', '.py')):\n"
            "            continue\n"
            "        if os.sep + 'Temp' + os.sep in d or d.endswith(os.sep + 'Temp'):\n"
            "            continue\n"
            "        src = os.path.join(d, name)\n"
            + action + "\n"
            "print('processed', n)\n")


def _python_task(code, imports="import os"):
    """
    Write the program to a file and run it, rather than passing it with -c.

    A one-liner on the command line would put the whole thing in the process
    arguments, where the sandbox records it as a string; writing it out means
    the interpreter reads a script from disk the way it normally would. The
    file is left behind, which is also what an ordinary tool does.
    """
    lines = ['echo running a python task',
             r'set PYSRC=%TEMP%\task_%RANDOM%.py',
             'break > "%PYSRC%"']
    for line in (imports + "\n" + code).rstrip("\n").split("\n"):
        safe = (line.replace("^", "^^").replace("&", "^&").replace("<", "^<")
                    .replace(">", "^>").replace("|", "^|").replace("%", "%%"))
        lines.append(f'echo.{safe}>> "%PYSRC%"' if safe else 'echo.>> "%PYSRC%"')
    for i, exe in enumerate(PYTHON):
        guard = "if exist" if i == 0 else "if not defined RANPY if exist"
        if exe == "python.exe":
            lines.append('if not defined RANPY (set RANPY=1& python "%PYSRC%")')
        else:
            lines.append(f'{guard} "{exe}" (set RANPY=1& "{exe}" "%PYSRC%")')
    lines.append('if not defined RANPY echo python not found')
    return "\n".join(lines)


def app_bat(task, root, count=None):
    fn = APP_TASKS[task][1]
    body = fn(root) if count is None else fn(root, count)
    return ("@echo off\r\n"
            "rem Ordinary use of software installed on this machine.\r\n"
            "setlocal enabledelayedexpansion\r\n"
            + body.replace("\n", "\r\n") + "\r\necho finished\r\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=60)
    parser.add_argument("--outdir", default="./scripts")
    parser.add_argument("--no-apps", action="store_true",
                         help="Skip the batch files that drive 7-Zip, Chrome, "
                              "Acrobat and Office")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(args.seed)

    # Enumerate the full grid and sample from it, so that the four languages
    # stay balanced against each other -- the point of the set is comparing
    # them, which needs the other factors to match across languages.
    grid = [(lang, m, s, l)
            for lang in LANGUAGES
            for m in METHODS
            for s in SCOPES
            for l in LIMITS]
    rng.shuffle(grid)
    chosen = grid[:args.count]

    rows = []

    # The application tasks come first and are always all included: there are
    # only eight and each is a distinct program doing a distinct thing, so
    # sampling them would leave gaps that matter.
    if not args.no_apps:
        # Two groups with different purposes, sized differently.
        #
        # 7-Zip and Python do the same shapes the compiled grid does, so they
        # belong to the language comparison and are matched to it: shapes at
        # two volumes, on the same profile-wide target. 7-Zip cannot do every
        # shape -- it is an archiver, so it has no in-place write -- and the
        # shapes it can do are the ones it is given.
        #
        # Chrome, Acrobat and Office are not part of that comparison at all.
        # They are there because a person opening a folder of documents is a
        # thing that happens, and the resulting file activity has no
        # counterpart anywhere else in the set. Two scopes each is enough;
        # spreading them wider would be repetition.
        user_activity = {"chrome_local", "acrobat_open", "office_open"}
        grid_matched = {"7z_encrypt_delete", "7z_encrypt_keep", "7z_perfile",
                        "python_copy_delete", "python_read_only",
                        "python_scratch"}
        for task, (desc, _fn) in APP_TASKS.items():
            if task in user_activity:
                scopes = ["desktop", "documents"]
            elif task in grid_matched:
                scopes = ["documents", "profile"]
            else:
                scopes = ["profile"]
            # The document viewers also vary in how many files they are
            # given, since opening three and opening twenty are different
            # amounts of work by the same signed program -- which is the
            # volume axis, expressed the way a person would produce it.
            counts = [3, 12] if task in user_activity else [None]
            for sc in scopes:
                for cnt in counts:
                    tag = f"_{cnt}" if cnt else ""
                    name = f"s_app_{task}_{sc}{tag}.bat"
                    path = os.path.join(outdir, name)
                    with open(path, "w", newline="") as f:
                        f.write(app_bat(task, APP_SCOPES[sc], cnt))
                    rows.append({"filename": name, "language": "app",
                                  "method": task, "scope": sc,
                                  "limit": cnt or 0,
                                  "description": f"{desc}, under {sc}",
                                  "bytes": os.path.getsize(path)})

    for lang, method, scope, limit in chosen:
        tag = f"{limit if limit else 'all'}"
        name = f"s_{lang}_{method}_{scope}_{tag}.{lang}"
        path = os.path.join(outdir, name)
        with open(path, "w", newline="\r\n") as f:
            f.write(LANGUAGES[lang](method, scope, limit))
        rows.append({"filename": name, "language": lang, "method": method,
                      "scope": scope, "limit": limit,
                      "description": f"{METHODS[method]}, under {scope}, "
                                     f"{'all files' if not limit else str(limit) + ' files'}",
                      "bytes": os.path.getsize(path)})

    manifest = os.path.join(outdir, "script_manifest.csv")
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "language", "method",
                                           "scope", "limit", "description", "bytes"])
        w.writeheader(); w.writerows(rows)

    print(f"{len(rows)} scripts in {outdir}")
    for k in ("language", "method", "scope"):
        print(f"   {k:<10}{dict(sorted(Counter(r[k] for r in rows).items()))}")
    print(f"[saved] {manifest}")
    print()
    print("Submit without naming a package; the extension picks the handler.")
    print("The process the sandbox records will be powershell.exe, wscript.exe")
    print("or cmd.exe, which is the point: the static features describe the")
    print("interpreter and say nothing about what the script does with files.")


if __name__ == "__main__":
    main()
