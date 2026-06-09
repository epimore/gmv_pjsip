use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let root = find_pjsip_root();
    let include_dir = root.join("include");
    let lib_dir = root.join("lib");

    assert!(include_dir.join("pjsip.h").exists(), "PJSIP header not found: {}. Set PJSIP_ROOT to pjproject dist prefix.", include_dir.join("pjsip.h").display());
    assert!(lib_dir.exists(), "PJSIP lib dir not found: {}", lib_dir.display());

    println!("cargo:rerun-if-env-changed=PJSIP_ROOT");
    println!("cargo:rerun-if-env-changed=PJSIP_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PJSIP_INCLUDE_DIR");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    link_pjproject_static_libs(&lib_dir);
    link_system_libs();

    #[cfg(feature = "bindgen")]
    generate_bindings(&include_dir);

    #[cfg(not(feature = "bindgen"))]
    {
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
        fs::write(out_path, "/* bindgen feature disabled: no bindings generated */\n").unwrap();
    }
}

fn find_pjsip_root() -> PathBuf {
    if let Ok(root) = env::var("PJSIP_ROOT") {
        return PathBuf::from(root);
    }

    // Workspace layout: <gmv>/crates/gmv_pjsip_sys -> <gmv>/third_party/pjproject-*/dist
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let gmv_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("failed to locate workspace root")
        .to_path_buf();
    let third_party = gmv_root.join("third_party");

    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir(&third_party) {
        for entry in entries.flatten() {
            let p = entry.path().join("dist");
            if p.join("include/pjsip.h").exists() && p.join("lib").exists() {
                candidates.push(p);
            }
        }
    }
    candidates.sort();
    candidates.pop().unwrap_or_else(|| third_party.join("pjproject-2.17/dist"))
}

fn link_pjproject_static_libs(lib_dir: &Path) {
    // PJSIP installs libraries as lib<name>-<target>.a, e.g.
    // libpjsip-x86_64-unknown-linux-gnu.a. We discover the actual archive names.
    let wanted_prefixes = [
        "pjsua2",
        "pjsua",
        "pjsip-ua",
        "pjsip-simple",
        "pjsip",
        "pjmedia-codec",
        "pjmedia-videodev",
        "pjmedia-audiodev",
        "pjmedia",
        "pjnath",
        "pjlib-util",
        "pj",
    ];

    let mut archives = Vec::new();
    for prefix in wanted_prefixes {
        if let Some(name) = find_archive_link_name(lib_dir, prefix) {
            archives.push(name);
        }
    }

    if archives.is_empty() {
        panic!("no pjproject static archives found in {}", lib_dir.display());
    }

    for name in archives {
        println!("cargo:rustc-link-lib=static={name}");
    }
}

fn find_archive_link_name(lib_dir: &Path, prefix: &str) -> Option<String> {
    let exact = lib_dir.join(format!("lib{prefix}.a"));
    if exact.exists() {
        return Some(prefix.to_string());
    }

    let mut matches = Vec::new();
    let entries = fs::read_dir(lib_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("a")) {
            continue;
        }
        let Some(file) = path.file_name().and_then(|s| s.to_str()) else { continue };
        if file.starts_with(&format!("lib{prefix}-")) && file.ends_with(".a") {
            matches.push(file.trim_start_matches("lib").trim_end_matches(".a").to_string());
        }
    }
    matches.sort();
    matches.pop()
}

fn link_system_libs() {
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("linux") {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=rt");
    } else if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=AudioToolbox");
        println!("cargo:rustc-link-lib=framework=AVFoundation");
    } else if target.contains("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=winmm");
    }
}

#[cfg(feature = "bindgen")]
fn generate_bindings(include_dir: &Path) {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", include_dir.display()))
        .allowlist_function("pj_.*")
        .allowlist_function("pjsip_.*")
        .allowlist_function("pjsua_.*")
        .allowlist_type("pj_.*")
        .allowlist_type("pjsip_.*")
        .allowlist_type("pjsua_.*")
        .allowlist_var("PJ_.*")
        .allowlist_var("PJSIP_.*")
        .allowlist_var("PJSUA_.*")
        .blocklist_type("max_align_t")
        .derive_default(true)
        .generate()
        .expect("failed to generate pjproject bindings");
    bindings.write_to_file(out_path).expect("failed to write bindings");
}
