/*
 * hardneg_stages.c - The same work, cut off at a different point each time.
 *
 * The argument this exists to test
 * --------------------------------
 * Every individual thing ransomware does is something ordinary software also
 * does. Walking a directory tree is what a backup tool does. Reading a file
 * and writing it back is what an editor does. Deleting the original after
 * producing a replacement is what an archiver does with -sdel. Stopping a
 * service is what an installer does. Writing a file into every folder is
 * what a licence tool does. Setting the wallpaper is what a theme does.
 * Removing shadow copies is what disk cleanup does.
 *
 * None of them is evidence. The claim is that the combination is, and that
 * claim has never been tested against anything that does some but not all of
 * it. The benign set cannot test it: those programs mostly exit within
 * seconds and score zero on every axis, so any feature separates them and
 * none of them says which feature was doing the work.
 *
 * This builds seven binaries. Each does everything the one below it does and
 * one thing more:
 *
 *   1  enumerate and read                    a scanner
 *   2  + write each file back in place       cipher /e, an editor
 *   3  + delete the original after writing   7z -sdel, an archiver
 *   4  + rename onto a shared new extension  a migration script
 *   5  + drop the same note in every folder  a licence tool
 *   6  + change the wallpaper                a theme installer
 *   7  + remove shadow copies                disk cleanup
 *
 * Running each and recording where the detector starts firing gives the
 * number the argument needs: how many of these an ordinary program can do
 * before it is indistinguishable from ransomware. If stage 3 already trips
 * it, file operations alone are enough and the corroboration rule is not
 * doing what it was built for. If nothing trips until 5 or 6, the
 * combination is carrying the decision.
 *
 * Compiled separately rather than switched at runtime by a flag, so that
 * each stage is its own binary with its own hash and its own import table.
 * One binary run seven ways would appear seven times under one sha256, and
 * the static features -- which APIs it needed at all -- would be identical
 * across stages when that difference is part of what is being measured.
 *
 * Nothing here is obfuscated, packed, or evasive. It is meant to be read.
 *
 * Build:
 *   for n in 1 2 3 4 5 6 7; do
 *     x86_64-w64-mingw32-gcc -O2 -DSTAGES=$n -municode \
 *       -o stage$n.exe hardneg_stages.c
 *   done
 */

#ifndef STAGES
#define STAGES 1
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_FILES        400
#define READ_CHUNK       65536
#define NEW_EXTENSION    ".staged"
#define NOTE_NAME        "RESTORE_INSTRUCTIONS.txt"

static const char *NOTE_TEXT =
    "This folder was processed by a staged behaviour test.\r\n"
    "\r\n"
    "Nothing here is encrypted and nothing is being demanded. The file\r\n"
    "exists so that a detector looking for a note dropped across many\r\n"
    "directories has one to find, in a run that is otherwise harmless.\r\n";

/* The directories the sandbox seeds with decoy files, so this operates on
 * exactly what a sample would find. */
static const char *TARGET_DIRS[] = {
    "%USERPROFILE%\\Desktop",
    "%USERPROFILE%\\Documents",
    "%USERPROFILE%\\Downloads",
    "%USERPROFILE%\\Pictures",
};
static const int TARGET_DIR_COUNT = 4;

static char  g_files[MAX_FILES][MAX_PATH];
static int   g_file_count = 0;
static char  g_dirs[64][MAX_PATH];
static int   g_dir_count = 0;

static void log_line(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

/* ---- stage 1: enumerate and read ------------------------------------ */

static void remember_dir(const char *dir)
{
    if (g_dir_count >= 64) return;
    for (int i = 0; i < g_dir_count; i++)
        if (_stricmp(g_dirs[i], dir) == 0) return;
    strncpy(g_dirs[g_dir_count], dir, MAX_PATH - 1);
    g_dirs[g_dir_count][MAX_PATH - 1] = '\0';
    g_dir_count++;
}

static void walk(const char *dir, int depth)
{
    if (depth > 3 || g_file_count >= MAX_FILES) return;

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA found;
    HANDLE h = FindFirstFileA(pattern, &found);
    if (h == INVALID_HANDLE_VALUE) return;

    remember_dir(dir);
    do {
        if (strcmp(found.cFileName, ".") == 0 || strcmp(found.cFileName, "..") == 0)
            continue;

        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", dir, found.cFileName);

        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk(full, depth + 1);
        } else if (g_file_count < MAX_FILES) {
            /* Skip anything already carrying our own extension, so a second
             * run does not process its own output. */
            size_t len = strlen(found.cFileName);
            size_t ext = strlen(NEW_EXTENSION);
            if (len > ext && _stricmp(found.cFileName + len - ext, NEW_EXTENSION) == 0)
                continue;
            if (_stricmp(found.cFileName, NOTE_NAME) == 0)
                continue;
            strncpy(g_files[g_file_count], full, MAX_PATH - 1);
            g_files[g_file_count][MAX_PATH - 1] = '\0';
            g_file_count++;
        }
    } while (FindNextFileA(h, &found) && g_file_count < MAX_FILES);

    FindClose(h);
}

static DWORD read_file(const char *path, BYTE *buffer, DWORD capacity)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD got = 0;
    ReadFile(h, buffer, capacity, &got, NULL);
    CloseHandle(h);
    return got;
}

/* ---- stage 2: write the contents back ------------------------------- */
#if STAGES >= 2
/* Byte for byte the same content. The point is the shape of the file
 * operations, not what ends up in the file -- an editor saving an unchanged
 * document produces this exact trail. */
static int write_file(const char *path, const BYTE *buffer, DWORD length)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD written = 0;
    WriteFile(h, buffer, length, &written, NULL);
    CloseHandle(h);
    return written == length;
}
#endif

/* ---- stage 5: a note in every directory ----------------------------- */
#if STAGES >= 5
static void drop_notes(void)
{
    int written = 0;
    for (int i = 0; i < g_dir_count; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", g_dirs[i], NOTE_NAME);
        HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD n = 0;
        WriteFile(h, NOTE_TEXT, (DWORD)strlen(NOTE_TEXT), &n, NULL);
        CloseHandle(h);
        written++;
    }
    log_line("[5] note written into %d directories", written);
}
#endif

/* ---- stage 6: the wallpaper ----------------------------------------- */
#if STAGES >= 6
static void change_wallpaper(void)
{
    char path[MAX_PATH];
    if (!ExpandEnvironmentStringsA("%TEMP%\\staged_wallpaper.bmp",
                                    path, sizeof(path))) return;

    /* A 2x2 bitmap is enough to be a real image file. */
    BYTE bmp[] = {
        0x42,0x4D,0x46,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,
        0x28,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,
        0x18,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x13,0x0B,0x00,0x00,
        0x13,0x0B,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x20,0x20,0x20,0x20,0x20,0x20,0x00,0x00,
        0x20,0x20,0x20,0x20,0x20,0x20,0x00,0x00,
    };
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD n = 0;
    WriteFile(h, bmp, sizeof(bmp), &n, NULL);
    CloseHandle(h);

    SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, path,
                          SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    log_line("[6] wallpaper set to %s", path);
}
#endif

/* ---- stage 7: shadow copies ----------------------------------------- */
#if STAGES >= 7
static void remove_shadow_copies(void)
{
    /* The same command a disk cleanup routine would run, and the same one
     * every family in the sample set runs. Run through cmd so it appears in
     * executed_commands the way a sample's would. */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    char cmd[] = "cmd.exe /c vssadmin.exe delete shadows /all /quiet";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        log_line("[7] shadow copy deletion requested");
    }
}
#endif

/* --------------------------------------------------------------------- */

int main(void)
{
    log_line("staged behaviour test, stages 1..%d", STAGES);

    /* A pause before anything, so the analysis captures a settled machine
     * first -- the same courtesy the sandbox gives every other sample. */
    Sleep(3000);

    for (int i = 0; i < TARGET_DIR_COUNT; i++) {
        char dir[MAX_PATH];
        if (!ExpandEnvironmentStringsA(TARGET_DIRS[i], dir, sizeof(dir)))
            continue;
        walk(dir, 0);
    }
    log_line("[1] found %d files across %d directories", g_file_count, g_dir_count);

    BYTE *buffer = (BYTE *)malloc(READ_CHUNK);
    if (!buffer) return 1;

    int read_ok = 0, written = 0, deleted = 0, renamed = 0;

    for (int i = 0; i < g_file_count; i++) {
        DWORD length = read_file(g_files[i], buffer, READ_CHUNK);
        if (!length) continue;
        read_ok++;

#if STAGES >= 3
        /* Write a replacement beside the original, then remove the
         * original -- an archiver with -sdel, or any tool that produces a
         * new file and cleans up after itself. */
        char replacement[MAX_PATH];
        snprintf(replacement, sizeof(replacement), "%s.tmpout", g_files[i]);
        if (write_file(replacement, buffer, length)) {
            written++;
            if (DeleteFileA(g_files[i])) deleted++;
#if STAGES >= 4
            /* Put every output onto one new extension. A migration script
             * marking processed files does exactly this. */
            char final_name[MAX_PATH];
            snprintf(final_name, sizeof(final_name), "%s%s",
                     g_files[i], NEW_EXTENSION);
            if (MoveFileA(replacement, final_name)) renamed++;
#endif
        }
#elif STAGES >= 2
        /* Write the same bytes back over the original. An editor saving an
         * unchanged file, or cipher /e turning on encryption in place. */
        if (write_file(g_files[i], buffer, length)) written++;
#endif
        if ((i % 25) == 0) Sleep(10);
    }

    free(buffer);
    log_line("[1] read %d", read_ok);
#if STAGES >= 2
    log_line("[2] wrote %d", written);
#endif
#if STAGES >= 3
    log_line("[3] deleted %d originals", deleted);
#endif
#if STAGES >= 4
    log_line("[4] renamed %d onto %s", renamed, NEW_EXTENSION);
#endif
#if STAGES >= 5
    drop_notes();
#endif
#if STAGES >= 6
    change_wallpaper();
#endif
#if STAGES >= 7
    remove_shadow_copies();
#endif

    log_line("done");
    return 0;
}
