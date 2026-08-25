// build.rs - Bake the grid parameters into the binary at compile time.
//
// The parameters have to be constants rather than arguments so that each
// variant is a distinct executable with its own hash and its own import
// table, matching how the C and Go variants are produced. A single binary
// reading its configuration at runtime would give the whole grid one row in
// the feature table, repeated.
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out = env::var("OUT_DIR").unwrap();
    let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
    let body = format!(
        "const SHAPE: usize = {};\n\
         const LIMIT: usize = {};\n\
         const ORDER: usize = {};\n\
         const TIMING: usize = {};\n\
         const EFFECTS: usize = {};\n\
         #[allow(dead_code)]\n\
         const BUILD_REP: usize = {};\n",
        get("HN_SHAPE", "1"),
        get("HN_LIMIT", "200"),
        get("HN_ORDER", "0"),
        get("HN_TIMING", "0"),
        get("HN_EFFECTS", "0"),
        get("HN_REP", "0"),
    );
    fs::write(Path::new(&out).join("params.rs"), body).unwrap();
    for k in ["HN_SHAPE", "HN_LIMIT", "HN_ORDER", "HN_TIMING", "HN_EFFECTS",
              "HN_REP"] {
        println!("cargo:rerun-if-env-changed={}", k);
    }
}
