use std::{
    env, fs,
    path::{Path, PathBuf},
};

const DEFAULT_PJSIP_VERSION: &str = "2.17";

fn main() {
    println!("cargo:rerun-if-env-changed=PJSIP_ROOT");
    println!("cargo:rerun-if-env-changed=GMV_ROOT");
    println!("cargo:rerun-if-env-changed=PJSIP_VERSION");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    let version = env::var("PJSIP_VERSION").unwrap_or_else(|_| DEFAULT_PJSIP_VERSION.to_string());

    let pjsip_root = find_pjsip_root(&version).unwrap_or_else(|| {
        panic!(
            "\nPJSIP not found.\n\
             Expected one of:\n\
             1) PJSIP_ROOT=/path/to/pjproject/dist\n\
             2) GMV_ROOT/third_party/pjproject-{version}/dist\n\n\
             Current crate is probably a git dependency, so CARGO_MANIFEST_DIR points to \
             ~/.cargo/git/checkouts/gmv_pjsip-... not your main gmv repository.\n\n\
             Please run:\n\
             cd /path/to/gmv\n\
             PJSIP_VERSION={version} ./scripts/build_pjsip_bootstrap.sh\n\
             export PJSIP_ROOT=/path/to/gmv/third_party/pjproject-{version}/dist\n"
        )
    });

    verify_pjsip_root(&pjsip_root);
    emit_link_flags(&pjsip_root);
    generate_bindings(&pjsip_root);
}

fn find_pjsip_root(version: &str) -> Option<PathBuf> {
    if let Some(root) = env::var_os("PJSIP_ROOT") {
        let root = PathBuf::from(root);
        if is_pjsip_root(&root) {
            return Some(root);
        }
    }

    if let Some(gmv_root) = env::var_os("GMV_ROOT") {
        let root = PathBuf::from(gmv_root)
            .join("third_party")
            .join(format!("pjproject-{version}"))
            .join("dist");

        if is_pjsip_root(&root) {
            return Some(root);
        }
    }

    None
}

fn is_pjsip_root(root: &Path) -> bool {
    root.join("include/pjsip.h").exists()
        && root.join("include/pjlib.h").exists()
        && has_static_libs(&root.join("lib"))
}

fn verify_pjsip_root(root: &Path) {
    assert!(
        root.join("include/pjsip.h").exists(),
        "pjsip.h not found under {}",
        root.join("include").display()
    );

    assert!(
        root.join("include/pjlib.h").exists(),
        "pjlib.h not found under {}",
        root.join("include").display()
    );

    assert!(
        has_static_libs(&root.join("lib")),
        "PJSIP static libs not found under {}",
        root.join("lib").display()
    );
}

fn has_static_libs(lib_dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(lib_dir) else {
        return false;
    };

    entries.flatten().any(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        name.starts_with("libpjsip") && name.ends_with(".a")
    })
}

fn emit_link_flags(root: &Path) {
    let lib_dir = root.join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    let mut libs = Vec::new();

    for entry in fs::read_dir(&lib_dir).expect("read PJSIP lib dir failed").flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        if name.starts_with("lib") && name.ends_with(".a") {
            libs.push(
                name.trim_start_matches("lib")
                    .trim_end_matches(".a")
                    .to_string(),
            );
        }
    }

    libs.sort();

    let ordered_prefixes = [
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

    let mut emitted = Vec::new();

    for prefix in ordered_prefixes {
        for lib in libs.iter().filter(|lib| lib.starts_with(prefix)) {
            println!("cargo:rustc-link-lib=static={lib}");
            emitted.push(lib.clone());
        }
    }

    for lib in libs {
        if !emitted.contains(&lib) {
            println!("cargo:rustc-link-lib=static={lib}");
        }
    }

    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=rt");
        println!("cargo:rustc-link-lib=uuid");
    }
}

fn generate_bindings(root: &Path) {
    let include_dir = root.join("include");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", include_dir.display()))

        // PJLIB
        .allowlist_function("pj_.*")
        .allowlist_type("pj_.*")
        .allowlist_var("PJ_.*")

        // PJLIB-UTIL
        // pjlib_util_init() 是 pjlib_ 前缀，不会被 pj_.* 匹配。
        // 后续 DNS、scanner、XML、hash、err code 等 PJLIB-UTIL 符号也依赖这里。
        .allowlist_function("pjlib_.*")
        .allowlist_type("pjlib_.*")
        .allowlist_var("PJLIB_.*")

        // PJSIP
        .allowlist_function("pjsip_.*")
        .allowlist_type("pjsip_.*")
        .allowlist_var("PJSIP_.*")

        // // PJNATH
        // .allowlist_function("pjnath_.*")
        // .allowlist_type("pjnath_.*")
        // .allowlist_var("PJNATH_.*")
        //
        // // PJMEDIA
        // .allowlist_function("pjmedia_.*")
        // .allowlist_type("pjmedia_.*")
        // .allowlist_var("PJMEDIA_.*")

        .generate()
        .expect("unable to generate PJSIP bindings");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("could not write bindings.rs");
}