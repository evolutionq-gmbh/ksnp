#![doc = include_str!("../README.md")]

#[allow(warnings)]
mod raw {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// Add in the C++ link crate to ensure it's libs are linked in, ksnp requires
// it.
#[expect(unused_extern_crates)]
extern crate link_cplusplus;

pub use raw::*;
