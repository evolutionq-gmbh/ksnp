QKD Key Stream Network Protocol Reference Implementation
========================================================

This library contains a reference implementation for the QKD key stream network
protocol (KSNP). It offers a C API that can be used to bind it to any language
that supports it, and requires little other than a working C++ runtime when
running.

Build Dependencies
------------------

This library is written in C++20 and requires a C++20-compatible compiler.
Furthermore, it makes use of the following additional libraries:

* [json-c](https://github.com/json-c/json-c)
* libuuid, which is part of the linux-utils package.

A CMake project is included that can be used to build the library and its
example applications.

Building the Library
--------------------

CMake is used to configure and build the library and its examples. Consult the
documentation of CMake for details on how to use it. To quickly get started,
you may use the following commands:

```shell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

By default documentation and examples are built/generated as well. This can be
controlled with the `BUILD_EXAMPLES` and `BUILD_DOCUMENTATION` project options.

Embedding the Library
---------------------

It is recommended to simply include this CMake project as a subdirectory of the
project it needs to be embedded into. It is then possible to link against the
`KSNP::ksnp` library target.

Alternatively, install this project into a prefix (usually `/usr/local` or
`/opt`) where your build system can find the necessary libraries and headers.

Using the Library API
---------------------

The API of the library can be roughly divided in three parts: Message
(de)serialization, server connection handling and client connection handling.

For message handling, the `ksnp_message_context` type defined in `serde.h` can
be used. This type can deserialize and serialize message data directly from byte
buffers, which in turn an application can use with its I/O channels.

To implement a server or client, use respectively `ksnp_server` or `ksnp_client`
from `server.h` or `client.h`. Data can be directly read from and written to
these types for I/O. For actual event handling, a processing function is
available that generates events. A server or client implementation then responds
to these events as appropriate.

The documentation of all header files provides further links to the usage of all
types.

Using the Examples
------------------

Included are an example server and client application. These primarily exist to
show how the library can be used, but may also be used to perform rudimentary
tests.

The server example requires an interface (as IP address) and port number to
start, and will listen for a single incoming connection on that interface and
port. It will accept any valid request to open a key stream, and send NUL bytes
as key data.

The client examples requires a hostname and port number to start, and will
connect to a server on that host and port. Once started, it reads commands from
the input. These can be any of the following:

* `open <target> [key-stream-id]`: Opens a new key stream with the given target
  as the destination SAE ID. If a key stream ID is specified, it will be sent to
  the server in the open request. The chunk size is fixed as 32 bytes per key.
* `get <key-id>`: Get a key from the stream, with an optional key ID. The key ID
  is the index of the key chunk to retrieve.
* `close`: Close the current key stream.
