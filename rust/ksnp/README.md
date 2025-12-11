Rust library for KSNP
=====================

This crate offers a wrapper for the KSNP library that allows it to be used from
other crates.

The most interesting types are [`ServerConnection`], [`ClientConnection`] and
[`MessageContext`]. These can be used to read from and write to I/O interfaces
and extract events from input data. Users of the library can use these events
to trigger actions that use one of the methods provided by these types.
