/*
 * hardneg_tools.c - Run the tools that are actually on the machine.
 *
 * Why this exists alongside the matrix
 * ------------------------------------
 * Everything in hardneg_matrix.c is code written for this experiment, and a
 * reviewer is entitled to ask whether a detector was tested against
 * programs built to test it. These are not that. 7-Zip, cipher, compact,
 * robocopy, certutil, findstr and Defender are on the guest already -- the
 * ransomware set walked past 7-Zip in 681 analyses and Adobe in 694 -- and
 * they are invoked here the way an administrator would invoke them.
 *
 * The interesting ones are those whose file behaviour is genuinely
 * indistinguishable from encryption:
 *
 *   7z with -mhe=on -sdel   reads every document, writes an encrypted
 *                           container, removes the originals. Read, write,
 *                           delete, with real cryptography in between. The
 *                           only thing separating it from ransomware is
 *                           that somebody asked for it.
 *
 *   cipher /e               turns on EFS. Files stay where they are, keep
 *                           their names, and become unreadable to every
 *                           other account. This is what AvosLocker looks
 *                           like from the filesystem's point of view, and
 *                           it is a Microsoft-signed binary.
 *
 *   compact /c              rewrites every file's contents in place. No
 *                           rename, no delete, and every byte changes.
 *
 * The rest are there as the other half of the comparison: robocopy /E and
 * findstr /s read just as much and destroy nothing, so a feature that fires
 * on volume alone cannot tell them from the three above.
 *
 * The tool runs as a child process, which is how ransomware invokes
 * vssadmin, so the events land in the analysis the same way.
 *
 * Build: see build_tools.sh
 */

#ifndef TOOL
#define TOOL 1
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILES 300
#define SEVENZIP  "C:\\Program Files\\7-Zip\\7z.exe"
/* Sysinternals tools are staged alongside this binary rather than installed,
 * so they sit wherever the analysis dropped them. */
#define SYSDIR    "C:\\Users\\admin\\AppData\\Local\\Temp"
#define DEFENDER  "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"
#define ARCHIVE_PASSWORD "archive-2026"

static char g_files[MAX_FILES][MAX_PATH];
static int  g_count = 0;

static void say(const char *fmt, ...)
{
    va_list a; va_start(a, fmt); vprintf(fmt, a); va_end(a);
    printf("\n"); fflush(stdout);
}

/* Wait for the tool rather than firing and forgetting, so its work lands
 * inside the analysis window instead of being cut off when this exits. */
static int run(const char *command, DWORD wait_ms)
{
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    char buf[2048];
    strncpy(buf, command, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        say("  could not start: %s", command);
        return 0;
    }
    WaitForSingleObject(pi.hProcess, wait_ms);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    say("  exit %lu", (unsigned long)code);
    return 1;
}

static void expand(const char *in, char *out, size_t n)
{
    if (!ExpandEnvironmentStringsA(in, out, (DWORD)n)) {
        strncpy(out, in, n - 1);
        out[n - 1] = '\0';
    }
}

static void collect(const char *dir, int depth)
{
    if (depth > 2 || g_count >= MAX_FILES) return;
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        char full[MAX_PATH];
        if (snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName)
                >= (int)sizeof(full)) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            collect(full, depth + 1);
        } else if (g_count < MAX_FILES) {
            strncpy(g_files[g_count], full, MAX_PATH - 1);
            g_files[g_count][MAX_PATH - 1] = '\0';
            g_count++;
        }
    } while (FindNextFileA(h, &fd) && g_count < MAX_FILES);
    FindClose(h);
}

static void collect_decoys(void)
{
    const char *roots[] = { "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", NULL };
    char dir[MAX_PATH];
    for (int i = 0; roots[i]; i++) {
        expand(roots[i], dir, sizeof(dir));
        collect(dir, 0);
    }
}

int main(void)
{
    char docs[MAX_PATH], desktop[MAX_PATH], profile[MAX_PATH], cmd[2048];
    expand("%USERPROFILE%\\Documents", docs, sizeof(docs));
    expand("%USERPROFILE%\\Desktop", desktop, sizeof(desktop));
    expand("%USERPROFILE%", profile, sizeof(profile));
    Sleep(3000);

#if TOOL == 1
    /* One encrypted container holding every document, sources removed.
     * Reads everything, writes one file, deletes the originals. */
    say("7z: encrypted archive of Documents, sources deleted");
    snprintf(cmd, sizeof(cmd),
             "\"%s\" a -p%s -mhe=on -y -sdel \"%s\\archive.7z\" \"%s\\*\"",
             SEVENZIP, ARCHIVE_PASSWORD, desktop, docs);
    run(cmd, 420000);

#elif TOOL == 2
    /* The same without -sdel. Identical reads and writes, nothing destroyed:
     * the control for the variant above. */
    say("7z: encrypted archive, sources kept");
    snprintf(cmd, sizeof(cmd),
             "\"%s\" a -p%s -mhe=on -y \"%s\\archive.7z\" \"%s\\*\"",
             SEVENZIP, ARCHIVE_PASSWORD, desktop, docs);
    run(cmd, 420000);

#elif TOOL == 3
    /* One archive per file, stored not compressed, original deleted. This is
     * the closest a legitimate tool gets to ransomware: a one-to-one
     * mapping, each output the size of its input, each original gone, each
     * new name the old name with something appended. */
    say("7z: one container per file, uncompressed, original deleted");
    collect_decoys();
    say("  %d files", g_count);
    for (int i = 0; i < g_count && i < 120; i++) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\" a -p%s -mhe=on -mx0 -y -sdel \"%s.7z\" \"%s\"",
                 SEVENZIP, ARCHIVE_PASSWORD, g_files[i], g_files[i]);
        run(cmd, 20000);
    }

#elif TOOL == 4
    /* EFS. Contents become unreadable to any other account, names and paths
     * unchanged -- the filesystem trail of an in-place encrypting family,
     * produced by a Microsoft-signed binary. */
    say("cipher /e on Documents and Desktop");
    snprintf(cmd, sizeof(cmd), "cmd.exe /c cipher.exe /e /a /s:\"%s\"", docs);
    run(cmd, 300000);
    snprintf(cmd, sizeof(cmd), "cmd.exe /c cipher.exe /e /a /s:\"%s\"", desktop);
    run(cmd, 300000);

#elif TOOL == 5
    /* NTFS compression: every byte of every file rewritten, in place, with
     * no rename and no delete. */
    say("compact /c on Documents");
    snprintf(cmd, sizeof(cmd), "cmd.exe /c compact.exe /c /s:\"%s\" /i /q", docs);
    run(cmd, 300000);

#elif TOOL == 6
    /* Reads the whole tree and writes a copy of it. Nothing is destroyed,
     * so the volume is comparable and the outcome is not. */
    say("robocopy /E, copy the tree");
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c robocopy.exe \"%s\" \"%s\\copy_of_docs\" /E /R:0 /W:0 /NFL /NDL",
             docs, desktop);
    run(cmd, 420000);

#elif TOOL == 7
    /* The same traversal, but the source is emptied. */
    say("robocopy /MOVE, relocate the tree");
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c robocopy.exe \"%s\" \"%s\\moved_docs\" /MOVE /E /R:0 /W:0 /NFL /NDL",
             docs, desktop);
    run(cmd, 420000);

#elif TOOL == 8
    /* certutil rewrites each file as base64 into a new file. Contents change
     * completely, size grows, the original stays. A signed Windows binary
     * doing a content transformation. */
    say("certutil -encode, per file");
    collect_decoys();
    say("  %d files", g_count);
    for (int i = 0; i < g_count && i < 120; i++) {
        snprintf(cmd, sizeof(cmd),
                 "cmd.exe /c certutil.exe -encode \"%s\" \"%s.b64\"",
                 g_files[i], g_files[i]);
        run(cmd, 15000);
    }

#elif TOOL == 9
    /* Reads everything, writes nothing. The pure-read control. */
    say("findstr /s, read every file");
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c findstr.exe /s /i /m \"zzzznotfound\" \"%s\\*\"", profile);
    run(cmd, 420000);

#elif TOOL == 10
    /* An antivirus scan opens every file in the tree and changes none of
     * them: the highest read volume available from a program nobody would
     * call suspicious. */
    say("Defender scan of the user profile");
    snprintf(cmd, sizeof(cmd),
             "\"%s\" -Scan -ScanType 3 -File \"%s\"", DEFENDER, profile);
    run(cmd, 480000);

#elif TOOL == 11
    /* PowerShell's own archive cmdlet: a different implementation of the
     * same read-many-write-one shape. */
    say("PowerShell Compress-Archive");
    snprintf(cmd, sizeof(cmd),
             "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
             "\"Compress-Archive -Path '%s\\*' -DestinationPath '%s\\docs.zip' -Force\"",
             docs, desktop);
    run(cmd, 420000);

#elif TOOL == 12
    /* Metadata only: attributes change, contents and names do not. */
    say("attrib +h across the tree");
    snprintf(cmd, sizeof(cmd), "cmd.exe /c attrib.exe +h \"%s\\*\" /s /d", docs);
    run(cmd, 240000);

#elif TOOL == 13
    /* Ownership and permissions across a tree -- what a migration or a
     * recovery from a broken ACL looks like. */
    say("takeown and icacls across Documents");
    snprintf(cmd, sizeof(cmd), "cmd.exe /c takeown.exe /f \"%s\" /r /d y", docs);
    run(cmd, 300000);
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c icacls.exe \"%s\" /grant %%USERNAME%%:F /t /c /q", docs);
    run(cmd, 300000);

#elif TOOL == 14
    /* xcopy: a third implementation of copying a tree. */
    say("xcopy the tree");
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c xcopy.exe \"%s\" \"%s\\xcopy_docs\\\" /E /I /Y /Q",
             docs, desktop);
    run(cmd, 420000);

#elif TOOL == 15
    /* Renaming a whole tree from the shell, no contents touched. */
    say("shell rename across the tree");
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c for /r \"%s\" %%f in (*) do @ren \"%%f\" \"%%~nxf.bak\"", docs);
    run(cmd, 300000);

#elif TOOL == 16
    /* Chrome headless: a large installed application starting, doing work
     * and exiting, with all the file activity that implies. */
    say("Chrome headless");
    snprintf(cmd, sizeof(cmd),
             "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" "
             "--headless --disable-gpu --no-sandbox --dump-dom about:blank");
    run(cmd, 120000);
    snprintf(cmd, sizeof(cmd),
             "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" "
             "--headless --disable-gpu --no-sandbox --dump-dom about:blank");
    run(cmd, 120000);

#elif TOOL == 17
    /* Several installed programs launched and closed, the ordinary activity
     * of a machine in use. */
    say("launch installed applications");
    run("cmd.exe /c start /wait notepad.exe", 20000);
    run("cmd.exe /c mspaint.exe", 20000);
    run("\"" SEVENZIP "\"", 20000);
    run("cmd.exe /c calc.exe", 20000);
    Sleep(20000);
    run("cmd.exe /c taskkill /f /im notepad.exe /im mspaint.exe "
        "/im calculator.exe /im 7zFM.exe", 20000);

#elif TOOL == 18
    /* A backup script: read the tree, write a dated copy, prune what is
     * older than a threshold. Reads, writes and deletes, for a reason
     * nobody would question. */
    say("backup and prune");
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c robocopy.exe \"%s\" \"%s\\backup_20260815\" /E /R:0 /W:0 /NFL /NDL",
             docs, desktop);
    run(cmd, 300000);
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c forfiles /p \"%s\" /s /m *.* /d -0 /c \"cmd /c del @path\"", docs);
    run(cmd, 300000);

#elif TOOL == 19
    /* Opening documents in whatever is registered to handle them. The decoy
     * set is real files -- pdf, docx, xlsx, pptx -- so this is a person
     * reading their own documents, and it produces exactly the reads a
     * family produces before it encrypts them. */
    say("open documents in their registered applications");
    collect_decoys();
    say("  %d files found", g_count);
    {
        int opened = 0;
        for (int i = 0; i < g_count && opened < 12; i++) {
            const char *e = strrchr(g_files[i], '.');
            if (!e) continue;
            if (_stricmp(e, ".pdf") && _stricmp(e, ".docx") &&
                _stricmp(e, ".xlsx") && _stricmp(e, ".pptx")) continue;
            snprintf(cmd, sizeof(cmd), "cmd.exe /c start \"\" \"%s\"", g_files[i]);
            run(cmd, 15000);
            opened++;
            Sleep(8000);
        }
        say("  opened %d, letting them settle", opened);
        Sleep(30000);
    }
    /* The same cleanup a family performs for the opposite reason: an open
     * document holds a lock, and the lock has to go before the file can be
     * touched. Identical API trail, entirely different purpose. */
    run("cmd.exe /c taskkill /f /im AcroRd32.exe /im Acrobat.exe /im WINWORD.EXE "
        "/im EXCEL.EXE /im POWERPNT.EXE /t", 60000);

#elif TOOL == 20
    /* Acrobat by path rather than by association, since Adobe is present in
     * 694 of the ransomware analyses and is the largest thing installed. */
    say("Acrobat on the decoy PDFs");
    collect_decoys();
    {
        const char *acrobat[] = {
            "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
            "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe",
            NULL };
        int opened = 0;
        for (int i = 0; i < g_count && opened < 8; i++) {
            const char *e = strrchr(g_files[i], '.');
            if (!e || _stricmp(e, ".pdf")) continue;
            for (int a = 0; acrobat[a]; a++) {
                if (GetFileAttributesA(acrobat[a]) == INVALID_FILE_ATTRIBUTES) continue;
                snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\"", acrobat[a], g_files[i]);
                run(cmd, 10000);
                opened++;
                break;
            }
            Sleep(6000);
        }
        say("  opened %d pdfs", opened);
        Sleep(30000);
    }
    run("cmd.exe /c taskkill /f /im Acrobat.exe /im AcroRd32.exe /im AcroCEF.exe /t", 60000);

#elif TOOL == 21
    /* Images and media through their handlers. */
    say("view images and play media");
    collect_decoys();
    {
        int opened = 0;
        for (int i = 0; i < g_count && opened < 10; i++) {
            const char *e = strrchr(g_files[i], '.');
            if (!e) continue;
            if (_stricmp(e, ".jpg") && _stricmp(e, ".png") && _stricmp(e, ".bmp") &&
                _stricmp(e, ".mp3") && _stricmp(e, ".mp4")) continue;
            snprintf(cmd, sizeof(cmd), "cmd.exe /c start \"\" \"%s\"", g_files[i]);
            run(cmd, 12000);
            opened++;
            Sleep(5000);
        }
        say("  opened %d", opened);
        Sleep(25000);
    }
    run("cmd.exe /c taskkill /f /im wmplayer.exe /im Microsoft.Photos.exe "
        "/im dllhost.exe /im PhotosApp.exe /t", 60000);

#elif TOOL == 22
    /* A working session: open a few things, leave them a while, close them,
     * open a few more. Repeated reads of the same paths, interleaved with
     * application startup, spread across minutes. */
    say("a document working session");
    collect_decoys();
    for (int round = 0; round < 3; round++) {
        int opened = 0;
        for (int i = round * 4; i < g_count && opened < 4; i++) {
            const char *e = strrchr(g_files[i], '.');
            if (!e) continue;
            if (_stricmp(e, ".pdf") && _stricmp(e, ".docx") &&
                _stricmp(e, ".xlsx") && _stricmp(e, ".txt")) continue;
            snprintf(cmd, sizeof(cmd), "cmd.exe /c start \"\" \"%s\"", g_files[i]);
            run(cmd, 12000);
            opened++;
            Sleep(5000);
        }
        say("  round %d: opened %d", round + 1, opened);
        Sleep(40000);
        run("cmd.exe /c taskkill /f /im AcroRd32.exe /im Acrobat.exe /im WINWORD.EXE "
            "/im EXCEL.EXE /im notepad.exe /t", 45000);
        Sleep(5000);
    }

#elif TOOL == 23
    /* Killing the applications that hold file locks, and nothing else.
     * A family does this so it can encrypt what they were holding; a backup
     * tool does it so it can copy a consistent snapshot. The process trail
     * is the same either way, which is the point of running it on its own. */
    say("release file locks by force, and stop there");
    run("cmd.exe /c start \"\" notepad.exe", 10000);
    run("cmd.exe /c start \"\" mspaint.exe", 10000);
    run("cmd.exe /c start \"\" \"" SEVENZIP "\"", 10000);
    Sleep(20000);
    run("cmd.exe /c taskkill /f /im notepad.exe /im mspaint.exe /im 7zFM.exe "
        "/im WINWORD.EXE /im EXCEL.EXE /im POWERPNT.EXE /im Acrobat.exe "
        "/im AcroRd32.exe /im outlook.exe /im sqlservr.exe /t", 90000);
    run("cmd.exe /c net stop MSSQLSERVER /y", 60000);
    run("cmd.exe /c net stop VSS /y", 60000);

#elif TOOL == 24
    /* Internet Explorer and Media Player rendering local files, which is
     * ordinary use of two programs the guest has installed. */
    say("Internet Explorer and Media Player on local files");
    collect_decoys();
    {
        int opened = 0;
        for (int i = 0; i < g_count && opened < 6; i++) {
            const char *e = strrchr(g_files[i], '.');
            if (!e) continue;
            if (_stricmp(e, ".txt") && _stricmp(e, ".csv") && _stricmp(e, ".pdf"))
                continue;
            snprintf(cmd, sizeof(cmd),
                     "\"C:\\Program Files\\Internet Explorer\\iexplore.exe\" \"file:///%s\"",
                     g_files[i]);
            run(cmd, 10000);
            opened++;
            Sleep(6000);
        }
        say("  opened %d in IE", opened);
    }
    run("\"C:\\Program Files\\Windows Media Player\\wmplayer.exe\"", 15000);
    Sleep(25000);
    run("cmd.exe /c taskkill /f /im iexplore.exe /im wmplayer.exe /t", 60000);

#elif TOOL == 25
    /* sdelete on the decoy documents.
     *
     * This is the sharpest case in the set. The tool exists to make a file
     * unrecoverable: it overwrites the contents, several times, and then
     * removes the entry. That is the trail m7_wipe was written to imitate,
     * and here it is produced by a binary Microsoft signs and distributes.
     *
     * If the detector fires, it is a false positive on the administrator's
     * own toolkit. If it does not, then overwriting and deleting every
     * document in a folder is not sufficient to be called ransomware, which
     * is a claim the ransomware results would struggle to support. */
    say("sdelete on the decoy documents");
    collect_decoys();
    say("  %d files", g_count);
    {
        int n = 0;
        for (int i = 0; i < g_count && n < 60; i++) {
            snprintf(cmd, sizeof(cmd),
                     "\"%s\\sdelete64.exe\" -accepteula -p 2 -nobanner \"%s\"",
                     SYSDIR, g_files[i]);
            if (!run(cmd, 20000)) {
                snprintf(cmd, sizeof(cmd),
                         "\"%s\\sdelete.exe\" -accepteula -p 2 -nobanner \"%s\"",
                         SYSDIR, g_files[i]);
                run(cmd, 20000);
            }
            n++;
        }
        say("  %d files passed to sdelete", n);
    }

#elif TOOL == 26
    /* du: walk the whole profile measuring directory sizes. Opens
     * everything, changes nothing, and produces read volume comparable to a
     * family enumerating its targets. */
    say("du across the user profile");
    snprintf(cmd, sizeof(cmd),
             "\"%s\\du64.exe\" -accepteula -nobanner -l 6 \"%s\"", SYSDIR, profile);
    if (!run(cmd, 420000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\du.exe\" -accepteula -nobanner -l 6 \"%s\"", SYSDIR, profile);
        run(cmd, 420000);
    }

#elif TOOL == 27
    /* accesschk: read the security descriptor of every file in the tree. */
    say("accesschk across the user profile");
    snprintf(cmd, sizeof(cmd),
             "\"%s\\accesschk64.exe\" -accepteula -nobanner -s \"%s\"",
             SYSDIR, profile);
    if (!run(cmd, 420000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\accesschk.exe\" -accepteula -nobanner -s \"%s\"",
                 SYSDIR, profile);
        run(cmd, 420000);
    }

#elif TOOL == 28
    /* streams and sigcheck: two more full-tree readers, run together so the
     * volume is comparable to the destructive variants. */
    say("streams and sigcheck across the profile");
    snprintf(cmd, sizeof(cmd),
             "\"%s\\streams64.exe\" -accepteula -nobanner -s \"%s\"",
             SYSDIR, profile);
    if (!run(cmd, 240000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\streams.exe\" -accepteula -nobanner -s \"%s\"",
                 SYSDIR, profile);
        run(cmd, 240000);
    }
    snprintf(cmd, sizeof(cmd),
             "\"%s\\sigcheck64.exe\" -accepteula -nobanner -s -q \"%s\"",
             SYSDIR, profile);
    if (!run(cmd, 240000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\sigcheck.exe\" -accepteula -nobanner -s -q \"%s\"",
                 SYSDIR, profile);
        run(cmd, 240000);
    }

#elif TOOL == 29
    /* autoruns and handle: registry-wide and process-wide enumeration, the
     * discovery half of what a family does before it starts. */
    say("autoruns and handle");
    snprintf(cmd, sizeof(cmd),
             "\"%s\\autorunsc64.exe\" -accepteula -nobanner -a * -c", SYSDIR);
    if (!run(cmd, 300000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\autorunsc.exe\" -accepteula -nobanner -a * -c", SYSDIR);
        run(cmd, 300000);
    }
    snprintf(cmd, sizeof(cmd),
             "\"%s\\handle64.exe\" -accepteula -nobanner -a", SYSDIR);
    if (!run(cmd, 120000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\handle.exe\" -accepteula -nobanner -a", SYSDIR);
        run(cmd, 120000);
    }

#elif TOOL == 30
    /* pskill and pssuspend: stopping other processes, which is the
     * preparation step a family performs to release file locks. Same trail,
     * signed by Microsoft. */
    say("pskill and pssuspend on lock holders");
    run("cmd.exe /c start \"\" notepad.exe", 10000);
    run("cmd.exe /c start \"\" mspaint.exe", 10000);
    Sleep(15000);
    for (int i = 0; i < 2; i++) {
        const char *target = i ? "mspaint.exe" : "notepad.exe";
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\pskill64.exe\" -accepteula -nobanner %s", SYSDIR, target);
        if (!run(cmd, 30000)) {
            snprintf(cmd, sizeof(cmd),
                     "\"%s\\pskill.exe\" -accepteula -nobanner %s", SYSDIR, target);
            run(cmd, 30000);
        }
    }

#elif TOOL == 31
    /* Contig: defragment individual files.
     *
     * To defragment a file the tool reads its contents and writes them back
     * to a contiguous run, which at the filesystem layer is the same trail
     * AvosLocker leaves -- same path, same name, contents rewritten. The
     * difference is that one of them is signed by Microsoft and the user
     * asked for it.
     *
     * stage2 makes this point with code written for the experiment. Contig
     * makes it with a tool that shipped years before. */
    say("Contig rewrites each decoy file in place");
    collect_decoys();
    say("  %d files", g_count);
    {
        int n = 0;
        for (int i = 0; i < g_count && n < 80; i++) {
            snprintf(cmd, sizeof(cmd),
                     "\"%s\\Contig64.exe\" -accepteula -nobanner \"%s\"",
                     SYSDIR, g_files[i]);
            if (!run(cmd, 15000)) {
                snprintf(cmd, sizeof(cmd),
                         "\"%s\\Contig.exe\" -accepteula -nobanner \"%s\"",
                         SYSDIR, g_files[i]);
                run(cmd, 15000);
            }
            n++;
        }
        say("  %d files defragmented", n);
    }

#elif TOOL == 32
    /* strings: read every byte of every file looking for printable runs.
     * Read volume as high as anything in the ransomware set, writes of
     * zero. */
    say("strings across the user profile");
    snprintf(cmd, sizeof(cmd),
             "cmd.exe /c \"%s\\strings64.exe\" -accepteula -nobanner -s \"%s\" > nul",
             SYSDIR, profile);
    if (!run(cmd, 420000)) {
        snprintf(cmd, sizeof(cmd),
                 "cmd.exe /c \"%s\\strings.exe\" -accepteula -nobanner -s \"%s\" > nul",
                 SYSDIR, profile);
        run(cmd, 420000);
    }

#elif TOOL == 33
    /* ru: walk the registry recursively, the discovery step without any of
     * the file work that usually accompanies it. */
    say("ru across HKCU and HKLM software");
    snprintf(cmd, sizeof(cmd),
             "\"%s\\ru64.exe\" -accepteula -nobanner HKCU", SYSDIR);
    if (!run(cmd, 240000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\ru.exe\" -accepteula -nobanner HKCU", SYSDIR);
        run(cmd, 240000);
    }
    snprintf(cmd, sizeof(cmd),
             "\"%s\\ru64.exe\" -accepteula -nobanner HKLM\\SOFTWARE", SYSDIR);
    if (!run(cmd, 240000)) {
        snprintf(cmd, sizeof(cmd),
                 "\"%s\\ru.exe\" -accepteula -nobanner HKLM\\SOFTWARE", SYSDIR);
        run(cmd, 240000);
    }

#else
#error "unknown TOOL"
#endif

    say("done");
    return 0;
}
