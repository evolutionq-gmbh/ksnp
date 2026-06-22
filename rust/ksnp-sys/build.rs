//! Build script for `kstp-sys`. Builds the static library using CMake, and
//! generates bindings with `bindgen`.

use core::fmt::Write;
use std::{collections::HashMap, env, path::PathBuf};

use bindgen::Formatter;
use syn::{File, Item, Path, Type, TypePath, parse_file};

fn main() {
    let mut knsp_root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    knsp_root_dir.push("../..");

    let mut cmake_cfg = cmake::Config::new(&knsp_root_dir);
    let install_dir = cmake_cfg
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_DOCS", "OFF")
        .define("BUILD_TEST", "OFF")
        .build();

    let mut config_path = env::var_os("PKG_CONFIG_PATH").unwrap_or_default();
    if !config_path.is_empty() {
        #[cfg(not(target_os = "windows"))]
        config_path.push(":");
        #[cfg(target_os = "windows")]
        config_path.push(";");
    }
    config_path.push(install_dir.join("lib/pkgconfig"));
    // SAFETY: The build script runs on a single thread, so set_var is safe to
    // use.
    unsafe {
        env::set_var("PKG_CONFIG_PATH", config_path);
    };

    let lib_ksnp = pkg_config::Config::new()
        .statik(true)
        .cargo_metadata(true)
        .probe("ksnp")
        .expect("Did not find ksnp");

    assert!(
        lib_ksnp.version.starts_with("0.4"),
        "Unsupported library version {}",
        lib_ksnp.version
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
        // Note: Since this is not yet c23, the fixup_enum function below is
        // required.
        .clang_arg("-std=c17")
        .clang_args(
            lib_ksnp
                .include_paths
                .iter()
                .map(|p| format!("-I{}", p.display())),
        )
        .allowlist_item("ksnp_.*|KSNP_.*")
        .opaque_type("json_object")
        .anon_fields_prefix("anon_")
        .formatter(Formatter::None)
        .generate()
        .expect("Unable to generate bindings");

    let header_dir = knsp_root_dir.join("include");
    for header in &headers {
        println!(
            "cargo::rerun-if-changed={}",
            header_dir.join(header).display()
        );
    }

    let mut bindings_data = Vec::new();
    bindings.write(Box::new(&mut bindings_data)).unwrap();

    let mut bindings_text = String::from_utf8(bindings_data).unwrap();
    bindings_text = fixup_enums(&bindings_text).unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    std::fs::write(out_path.join("bindings.rs"), bindings_text).expect("Couldn't write bindings!");
}

/// Replace bindgen's generated enums and typedefs with something that compiles.
///
/// This works around an incompatibility between bindgen's newtype enum
/// handling, and the type alias used by KSNP for enums, which currently results
/// in the same name being used twice, and the newtype alias using the wrong
/// underlying type.
// When using C17 or earlier, enums are defined as
//
// ```C
// enum E { ... }; typedef uint#_t E;
// ```
//
// Ideally, this is resolved as a Rust type
//
// ```rust
// struct E(pub u#);
//
// impl E {
//     ...
// }
// ```
//
// but bindgen generates an additional type alias. To work around that, this
// function renames the type alias to `E_t`, and defines `E` as `struct E(pub
// E_t)`.
fn fixup_enums(source: &str) -> syn::Result<String> {
    let mut file: File = parse_file(source)?;

    let structs: HashMap<String, usize> = file
        .items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            let Item::Struct(strct) = item else {
                return None;
            };

            Some((strct.ident.to_string(), i))
        })
        .collect::<HashMap<_, _>>();

    let typedefs: HashMap<String, usize> = file
        .items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            let Item::Type(typ) = item else {
                return None;
            };

            Some((typ.ident.to_string(), i))
        })
        .collect::<HashMap<_, _>>();

    for (typ_name, typ_idx) in typedefs {
        let Some(strct_idx) = structs.get(&typ_name) else {
            continue;
        };

        let Ok([Item::Type(typedef), Item::Struct(strct)]) =
            file.items.get_disjoint_mut([typ_idx, *strct_idx])
        else {
            unreachable!();
        };

        typedef.ident = syn::Ident::new(&format!("{}_t", typedef.ident), typedef.ident.span());
        let Some(field) = strct.fields.iter_mut().next() else {
            continue;
        };
        field.ty = Type::Path(TypePath {
            qself: None,
            path: Path::from(typedef.ident.clone()),
        });
    }

    Ok(prettyplease::unparse(&file))
}
