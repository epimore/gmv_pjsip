use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
};

const PKG_CONFIG_NAME: &str = "libpjproject";
const MIN_PJPROJECT_VERSION: &str = "2.15.1";

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EnvVars {
    docs_rs: Option<String>,
    out_dir: Option<PathBuf>,
    pjsip_include_dir: Option<PathBuf>,
    pjsip_dll_path: Option<PathBuf>,
    pjsip_pkg_config_path: Option<PathBuf>,
    pjsip_libs_dir: Option<PathBuf>,
    pjsip_binding_path: Option<PathBuf>,
}

impl EnvVars {
    fn init() -> Self {
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-changed=wrapper.h");
        println!("cargo:rerun-if-changed=shim.h");
        println!("cargo:rerun-if-changed=shim.c");
        println!("cargo:rerun-if-changed=shim_commands.inc");
        println!("cargo:rerun-if-changed=shim_command_dispatch.inc");
        println!("cargo:rerun-if-changed=shim_transport.inc");
        println!("cargo:rerun-if-changed=shim_auth.inc");
        println!("cargo:rerun-if-changed=shim_message.inc");
        println!("cargo:rerun-if-changed=shim_invite.inc");
        println!("cargo:rerun-if-changed=shim_dialog.inc");
        println!("cargo:rerun-if-changed=shim_subscription.inc");
        println!("cargo:rerun-if-changed=src/bindings.rs");

        for name in [
            "DOCS_RS",
            "OUT_DIR",
            "PJSIP_INCLUDE_DIR",
            "PJSIP_DLL_PATH",
            "PJSIP_PKG_CONFIG_PATH",
            "PJSIP_LIBS_DIR",
            "PJSIP_BINDING_PATH",
        ] {
            println!("cargo:rerun-if-env-changed={name}");
        }

        Self {
            docs_rs: env::var("DOCS_RS").ok(),
            out_dir: env_path("OUT_DIR"),
            pjsip_include_dir: env_path("PJSIP_INCLUDE_DIR"),
            pjsip_dll_path: env_path("PJSIP_DLL_PATH"),
            pjsip_pkg_config_path: env_path("PJSIP_PKG_CONFIG_PATH"),
            pjsip_libs_dir: env_path("PJSIP_LIBS_DIR"),
            pjsip_binding_path: env_path("PJSIP_BINDING_PATH"),
        }
    }

    fn out_binding_path(&self) -> PathBuf {
        self.out_dir
            .as_ref()
            .expect("OUT_DIR is not set by Cargo")
            .join("bindings.rs")
    }

    fn has_prebuilt_binding(&self) -> bool {
        self.pjsip_binding_path.is_some()
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var(name).ok().map(remove_verbatim)
}

/// clang does not accept `\\?\` verbatim paths well on Windows.
fn remove_verbatim(path: String) -> PathBuf {
    let path = path
        .strip_prefix(r#"\\?\"#)
        .map(str::to_owned)
        .unwrap_or(path);
    PathBuf::from(path)
}

fn main() {
    let envs = EnvVars::init();
    let output_binding_path = envs.out_binding_path();

    if envs.docs_rs.is_some() {
        docs_rs_linking(&output_binding_path);
        return;
    }

    // Main application explicitly controls linking when these variables exist.
    // Priority: exact dynamic/import library path > explicit lib dir > explicit
    // pkg-config search path > default system pkg-config probe.
    let include_dirs = if let Some(dll_path) = envs.pjsip_dll_path.as_ref() {
        dynamic_linking(dll_path);
        collect_include_dirs_from_env(&envs)
    } else if let Some(libs_dir) = envs.pjsip_libs_dir.as_ref() {
        libs_dir_linking(libs_dir);
        collect_include_dirs_from_env(&envs)
    } else if let Some(pkg_config_path) = envs.pjsip_pkg_config_path.as_ref() {
        pkg_config_linking(Some(pkg_config_path), &envs)
    } else {
        // Default behavior: try pkg-config from the host/cross sysroot.
        // pkg-config does not download PJPROJECT. It discovers an installed
        // package and emits compile/link metadata. Main applications should
        // install/build PJPROJECT in CI, Docker, or a bootstrap script.
        pkg_config_linking(None, &envs)
    };

    compile_shim_if_possible(&include_dirs);
    write_bindings(&envs, &include_dirs, &output_binding_path);
}

fn docs_rs_linking(output_binding_path: &Path) {
    use_prebuilt_binding(Path::new("src/bindings.rs"), output_binding_path);
}

fn use_prebuilt_binding(from: &Path, to: &Path) {
    fs::copy(from, to).unwrap_or_else(|e| {
        panic!(
            "failed to copy prebuilt PJSIP binding from {} to {}: {e}",
            from.display(),
            to.display()
        )
    });
}

fn collect_include_dirs_from_env(envs: &EnvVars) -> Vec<PathBuf> {
    match envs.pjsip_include_dir.as_ref() {
        Some(dir) => {
            verify_include_dir(dir);
            vec![dir.clone()]
        }
        None if envs.has_prebuilt_binding() => Vec::new(),
        None => panic!(
            "PJSIP_INCLUDE_DIR is required for bindgen when using PJSIP_DLL_PATH or PJSIP_LIBS_DIR.\n\
             Or set PJSIP_BINDING_PATH=/path/to/pre-generated/bindings.rs."
        ),
    }
}

fn verify_include_dir(include_dir: &Path) {
    for header in ["pjlib.h", "pjlib-util.h", "pjsip.h"] {
        let path = include_dir.join(header);
        if !path.exists() {
            panic!(
                "PJSIP include header not found: {}\n\
                 Please set PJSIP_INCLUDE_DIR to the PJPROJECT install include directory.",
                path.display()
            );
        }
    }

    // Manual include/lib mode intentionally does not validate pj/version.h.
    // Installed PJPROJECT include trees do not consistently ship version metadata.
    // API availability is validated by compiling shim.c. pkg-config mode still
    // validates the libpjproject.pc version string.
}

fn dynamic_linking(dll_path: &Path) {
    if !dll_path.exists() {
        panic!("PJSIP_DLL_PATH does not exist: {}", dll_path.display());
    }

    let dll_dir = dll_path.parent().unwrap_or_else(|| {
        panic!(
            "PJSIP_DLL_PATH has no parent directory: {}",
            dll_path.display()
        )
    });

    let file_name = dll_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("invalid PJSIP_DLL_PATH filename: {}", dll_path.display()));

    let lib_name = dynamic_library_name(file_name);

    println!("cargo:rustc-link-search=native={}", dll_dir.display());
    println!("cargo:rustc-link-lib=dylib={lib_name}");

    emit_platform_system_libs();
}

fn dynamic_library_name(file_name: &str) -> String {
    let mut name = file_name.to_owned();

    for ext in [".dll.a", ".so", ".dylib", ".dll", ".lib", ".a"] {
        if let Some(stripped) = name.strip_suffix(ext) {
            name = stripped.to_owned();
            break;
        }
    }

    if !is_windows_target() {
        name = name.trim_start_matches("lib").to_owned();
    }

    name
}

fn libs_dir_linking(libs_dir: &Path) {
    if !libs_dir.is_dir() {
        panic!("PJSIP_LIBS_DIR is not a directory: {}", libs_dir.display());
    }

    println!("cargo:rustc-link-search=native={}", libs_dir.display());

    if let Some(lib) = find_single_project_library(libs_dir) {
        match lib.kind {
            LibraryKind::Static => println!("cargo:rustc-link-lib=static={}", lib.name),
            LibraryKind::Dynamic => println!("cargo:rustc-link-lib=dylib={}", lib.name),
        }
        emit_platform_system_libs();
        return;
    }

    let libs = collect_split_pj_static_libs(libs_dir);
    if libs.is_empty() {
        panic!(
            "no PJPROJECT library was found under {}.\n\
             Expected libpjproject.* or split static libraries such as libpjsip-*.a, libpj-*.a.",
            libs_dir.display()
        );
    }

    emit_ordered_static_pj_libs(&libs);
    emit_platform_system_libs();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LibraryCandidate {
    name: String,
    kind: LibraryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LibraryKind {
    Static,
    Dynamic,
}

fn find_single_project_library(libs_dir: &Path) -> Option<LibraryCandidate> {
    let candidates = [
        ("libpjproject.a", "pjproject", LibraryKind::Static),
        ("libpjproject.so", "pjproject", LibraryKind::Dynamic),
        ("libpjproject.dylib", "pjproject", LibraryKind::Dynamic),
        ("pjproject.lib", "pjproject", LibraryKind::Dynamic),
        ("pjproject.dll.lib", "pjproject", LibraryKind::Dynamic),
        ("libpjproject.dll.a", "pjproject", LibraryKind::Dynamic),
    ];

    for (file, name, kind) in candidates {
        if libs_dir.join(file).exists() {
            return Some(LibraryCandidate {
                name: name.to_owned(),
                kind,
            });
        }
    }

    None
}

fn collect_split_pj_static_libs(libs_dir: &Path) -> Vec<String> {
    let mut libs = Vec::new();

    for entry in fs::read_dir(libs_dir)
        .unwrap_or_else(|e| panic!("failed to read PJSIP_LIBS_DIR {}: {e}", libs_dir.display()))
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("lib") && name.ends_with(".a") {
            let lib = name
                .trim_start_matches("lib")
                .trim_end_matches(".a")
                .to_owned();
            if is_pjproject_split_lib(&lib) {
                libs.push(lib);
            }
        }
    }

    libs.sort();
    libs.dedup();
    libs
}

fn is_pjproject_split_lib(lib: &str) -> bool {
    [
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
    ]
    .iter()
    .any(|base| matches_pj_lib(lib, base))
}

fn emit_ordered_static_pj_libs(libs: &[String]) {
    // Higher-level libraries must be emitted before lower-level libraries.
    // PJNATH and PJMEDIA are kept in the order list so the crate can become a
    // complete PJPROJECT sys crate later. Their headers and bindgen allowlists
    // remain commented in wrapper.h/build.rs until the safe layer needs them.
    let order = [
        "pjsua2",
        "pjsua",
        "pjsip-ua",
        "pjsip-simple",
        "pjsip",
        // Future PJMEDIA modules. Kept active for linking if present because
        // libpjsua/libpjsip may depend on parts of them in some builds.
        "pjmedia-codec",
        "pjmedia-videodev",
        "pjmedia-audiodev",
        "pjmedia",
        // Future PJNATH module.
        "pjnath",
        "pjlib-util",
        "pj",
    ];

    let mut emitted = HashSet::new();

    for base in order {
        for lib in libs.iter().filter(|lib| matches_pj_lib(lib, base)) {
            if emitted.insert(lib.clone()) {
                println!("cargo:rustc-link-lib=static={lib}");
            }
        }
    }

    for lib in libs {
        if emitted.insert(lib.clone()) {
            println!("cargo:rustc-link-lib=static={lib}");
        }
    }
}

fn matches_pj_lib(lib: &str, base: &str) -> bool {
    lib == base || lib.starts_with(&format!("{base}-"))
}

fn pkg_config_linking(pkg_config_path: Option<&PathBuf>, envs: &EnvVars) -> Vec<PathBuf> {
    if let Some(path) = pkg_config_path {
        if !path.is_dir() {
            panic!(
                "PJSIP_PKG_CONFIG_PATH is not a directory: {}",
                path.display()
            );
        }
        env::set_var("PKG_CONFIG_PATH", path);
    }

    let library = pkg_config::Config::new()
        .cargo_metadata(true)
        .probe(PKG_CONFIG_NAME)
        .unwrap_or_else(|e| {
            let source = if let Some(path) = pkg_config_path {
                format!("PJSIP_PKG_CONFIG_PATH={}", path.display())
            } else {
                "default pkg-config search path".to_owned()
            };
            panic!(
                "pkg-config probe `{PKG_CONFIG_NAME}` failed from {source}: {e}\n\
                 PJPROJECT must already be installed/built. pkg-config discovers dependencies; it does not download them.\n\
                 Fix options:\n\
                   1) install pjproject development package; or\n\
                   2) build pjproject with --prefix=<dist> and set PJSIP_PKG_CONFIG_PATH=<dist>/lib/pkgconfig; or\n\
                   3) set PJSIP_INCLUDE_DIR and PJSIP_LIBS_DIR; or\n\
                   4) set PJSIP_DLL_PATH and PJSIP_INCLUDE_DIR."
            )
        });

    if version_less_than(&library.version, MIN_PJPROJECT_VERSION) {
        panic!(
            "pkg-config found `{PKG_CONFIG_NAME}` version {}, but gmv_pjsip_sys requires >= {MIN_PJPROJECT_VERSION} \
             for PJSIP digest helper APIs. PJPROJECT 2.17 is recommended. \
             Set PJSIP_PKG_CONFIG_PATH/PJSIP_INCLUDE_DIR/PJSIP_LIBS_DIR to the intended PJPROJECT build.",
            library.version
        );
    }

    let mut include_dirs: Vec<PathBuf> = library.include_paths;

    if let Some(dir) = envs.pjsip_include_dir.as_ref() {
        verify_include_dir(dir);
        include_dirs.insert(0, dir.clone());
    }

    if include_dirs.is_empty() && !envs.has_prebuilt_binding() {
        panic!(
            "pkg-config did not return include paths for `{PKG_CONFIG_NAME}`.\n\
             Please set PJSIP_INCLUDE_DIR or PJSIP_BINDING_PATH."
        );
    }

    include_dirs
}

fn version_less_than(found: &str, minimum: &str) -> bool {
    let found_parts = version_parts(found);
    let min_parts = version_parts(minimum);
    for idx in 0..found_parts.len().max(min_parts.len()) {
        let a = *found_parts.get(idx).unwrap_or(&0);
        let b = *min_parts.get(idx).unwrap_or(&0);
        if a < b {
            return true;
        }
        if a > b {
            return false;
        }
    }
    false
}

fn version_parts(version: &str) -> Vec<u32> {
    version
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .take(3)
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect()
}

fn compile_shim_if_possible(include_dirs: &[PathBuf]) {
    if include_dirs.is_empty() {
        println!(
            "cargo:warning=skip compiling PJSIP auth shim because no include dir is available"
        );
        return;
    }

    let mut build = cc::Build::new();
    build.file("shim.c");
    build.include(".");

    if !is_windows_target() {
        build.define("PJ_AUTOCONF", Some("1"));
    } else {
        build.define("PJ_WIN32", Some("1"));
    }

    for dir in include_dirs {
        build.include(dir);
    }

    // Keep downstream applications clean. PJPROJECT headers may emit harmless
    // warnings caused by config_site.h overrides. Real C compile errors still
    // fail the build. Set GMV_PJSIP_SYS_SHOW_C_WARNINGS=1 to inspect warnings.
    if env::var_os("GMV_PJSIP_SYS_SHOW_C_WARNINGS").is_some() {
        build.flag_if_supported("-Wno-unused-parameter");
        build.flag_if_supported("-Wno-macro-redefined");
    } else if is_msvc_target() {
        build.flag("/W0");
    } else {
        build.flag("-w");
    }

    build.compile("gmv_pjsip_auth_shim");
}

fn write_bindings(envs: &EnvVars, include_dirs: &[PathBuf], output_binding_path: &Path) {
    if let Some(binding_path) = envs.pjsip_binding_path.as_ref() {
        use_prebuilt_binding(binding_path, output_binding_path);
        return;
    }

    generate_bindings(include_dirs, output_binding_path);
}

#[cfg(feature = "bindgen")]
fn generate_bindings(include_dirs: &[PathBuf], output_binding_path: &Path) {
    if include_dirs.is_empty() {
        panic!(
            "no PJSIP include directory is available for bindgen.\n\
             Set PJSIP_INCLUDE_DIR, use pkg-config that returns include dirs, or set PJSIP_BINDING_PATH."
        );
    }

    for dir in include_dirs {
        verify_include_dir(dir);
    }

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-DPJ_AUTOCONF=1")
        .allowlist_function("pj_.*")
        .allowlist_function("pjlib_.*")
        .allowlist_function("pjsip_.*")
        .allowlist_function("gmv_pjsip_.*")
        .allowlist_function("gmv_sip_.*")
        .allowlist_type("pj_.*")
        .allowlist_type("pjlib_.*")
        .allowlist_type("pjsip_.*")
        .allowlist_type("gmv_pjsip_.*")
        .allowlist_type("gmv_sip_.*")
        .allowlist_var("GMV_SIP_.*")
        .allowlist_var("PJ_.*")
        .allowlist_var("PJLIB_.*")
        .allowlist_var("PJSIP_.*")
        // Reserved for later expansion. Also uncomment headers in wrapper.h.
        // .allowlist_function("pjnath_.*")
        // .allowlist_type("pjnath_.*")
        // .allowlist_var("PJNATH_.*")
        // .allowlist_function("pjmedia_.*")
        // .allowlist_type("pjmedia_.*")
        // .allowlist_var("PJMEDIA_.*")
        .derive_debug(true)
        .derive_default(true)
        .layout_tests(false);

    if is_windows_target() {
        builder = builder.clang_arg("-DPJ_WIN32=1");
    }

    for dir in include_dirs {
        builder = builder.clang_arg(format!("-I{}", dir.display()));
    }

    let bindings = builder
        .generate()
        .expect("failed to generate PJSIP bindings with bindgen");

    bindings
        .write_to_file(output_binding_path)
        .expect("failed to write generated PJSIP bindings");
}

#[cfg(not(feature = "bindgen"))]
fn generate_bindings(_include_dirs: &[PathBuf], _output_binding_path: &Path) {
    panic!(
        "gmv_pjsip_sys was built without the `bindgen` feature.\n\
         Please enable the `bindgen` feature or set PJSIP_BINDING_PATH."
    );
}

fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| env::consts::OS.to_owned())
}

fn target_env() -> String {
    env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default()
}

fn is_windows_target() -> bool {
    target_os() == "windows"
}

fn is_msvc_target() -> bool {
    is_windows_target() && target_env() == "msvc"
}

fn emit_platform_system_libs() {
    match target_os().as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=m");
            println!("cargo:rustc-link-lib=dl");
            println!("cargo:rustc-link-lib=rt");
            println!("cargo:rustc-link-lib=uuid");
        }
        "freebsd" | "openbsd" | "netbsd" => {
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=m");
        }
        "macos" | "ios" => {
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=m");
        }
        "windows" => {
            println!("cargo:rustc-link-lib=ws2_32");
            println!("cargo:rustc-link-lib=wsock32");
            println!("cargo:rustc-link-lib=ole32");
            println!("cargo:rustc-link-lib=uuid");
            println!("cargo:rustc-link-lib=winmm");
        }
        _ => {}
    }

    // PJPROJECT builds with TLS/SRTP/audio backends may need extra system libs.
    // Prefer pkg-config when possible, because libpjproject.pc carries the
    // exact dependencies selected by the PJPROJECT build.
}
