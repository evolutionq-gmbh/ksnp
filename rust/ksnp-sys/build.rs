//! Build script for `kstp-sys`. Builds the static library using CMake, and
//! generates bindings with `bindgen`.

use core::fmt::Write;
use std::{
    env,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use regex::Regex;

fn main() {
    let mut knsp_root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    knsp_root_dir.push("../..");

    // Find the dependencies required to parse the headers and build the CMake
    // project.
    let lib_uuid = pkg_config::Config::new()
        .atleast_version("2.38")
        .statik(true)
        .probe("uuid")
        .expect("Did not find libuuid");
    let lib_jsonc = pkg_config::Config::new()
        .atleast_version("0.18")
        .statik(true)
        .probe("json-c")
        .expect("Did not find libjson-c");

    // Ensure CMake tries to use the same dependencies as found by PkgConfig.
    let mut cmake_cfg = cmake::Config::new(&knsp_root_dir);
    let install_dir = cmake_cfg
        .generator("Ninja")
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_DOCS", "OFF")
        .define("BUILD_TEST", "OFF")
        .define("LibUUID_LIBRARY", lib_uuid.libs.join(";"))
        .define(
            "LibUUID_INCLUDE_DIR",
            lib_uuid
                .include_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(";"),
        )
        .define("JSONC_LIBRARY", lib_jsonc.libs.join(";"))
        .define(
            "JSONC_INCLUDE_DIR",
            lib_jsonc
                .include_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(";"),
        )
        .build();

    println!(
        "cargo:rustc-link-search=native={}",
        install_dir.join("lib").to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=ksnp");

    let include_path = install_dir.join("include");

    let re_major = Regex::new(r"^static int const KSNP_VERSION_MAJOR = (\d+);$").unwrap();
    let re_minor = Regex::new(r"^static int const KSNP_VERSION_MINOR = (\d+);$").unwrap();
    let mut version_major: Option<usize> = None;
    let mut version_minor: Option<usize> = None;
    let version_file = std::fs::File::open(include_path.join("ksnp/version.h"))
        .expect("Failed to read version file");
    for line in BufReader::new(version_file).lines() {
        let line = line.unwrap();
        if let Some(m) = re_major.captures(&line).and_then(|c| c.get(1)) {
            version_major = Some(m.as_str().parse().unwrap());
        } else if let Some(m) = re_minor.captures(&line).and_then(|c| c.get(1)) {
            version_minor = Some(m.as_str().parse().unwrap());
        }

        if version_major.is_some() && version_minor.is_some() {
            break;
        }
    }

    let (Some(version_major), Some(version_minor)) = (version_major, version_minor) else {
        panic!("Missing version information");
    };

    assert!(
        version_major == 0 && version_minor == 1,
        "Unsupported library version"
    );

    let headers = [
        "ksnp/client.h",
        "ksnp/messages.h",
        "ksnp/serde.h",
        "ksnp/server.h",
        "ksnp/types.h",
        "ksnp/version.h",
    ];

    let wrapper_string = headers
        .iter()
        .fold::<String, _>(String::new(), |mut acc, header| {
            writeln!(acc, r#"#include "{header}""#).unwrap();
            acc
        });

    // Generate Rust bindings
    let bindings = bindgen::Builder::default()
        .use_core()
        .layout_tests(false)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .header_contents("wrapper.h", &wrapper_string)
        .clang_arg(format!("-I{}", include_path.display()))
        .clang_arg("-std=c23")
        .clang_args(
            lib_uuid
                .include_paths
                .iter()
                .map(|p| format!("-I{}", p.display())),
        )
        .clang_args(
            lib_jsonc
                .include_paths
                .iter()
                .map(|p| format!("-I{}", p.display())),
        )
        .allowlist_item("ksnp_.*|KSNP_.*")
        .opaque_type("json_object")
        .anon_fields_prefix("anon_")
        .generate()
        .expect("Unable to generate bindings");

    for header in &headers {
        println!(
            "cargo::rerun-if-changed={}",
            include_path.join(header).display()
        );
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
