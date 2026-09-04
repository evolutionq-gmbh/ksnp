# Simple toolchain file to use a compiler inserting AFL instrumentation.

# Try to choose the LLVM-LTO mode; if we cannot detect that a sufficiently
# recent LLVM is installed, we fall back to an automatic selection via the
# `afl-cc` wrapper.
execute_process(COMMAND llvm-config --version OUTPUT_VARIABLE LLVM_INSTALLED_VERSION)
if (DEFINED LLVM_INSTALLED_VERSION AND "${LLVM_INSTALLED_VERSION}" VERSION_GREATER_EQUAL 13)
    find_program(AFL_C_COMPILER afl-clang-lto)
    find_program(AFL_CXX_COMPILER afl-clang-lto++)
else ()
    find_program(AFL_C_COMPILER afl-cc)
    find_program(AFL_CXX_COMPILER afl-c++)
endif ()

if (AFL_C_COMPILER AND AFL_CXX_COMPILER)
    set(CMAKE_C_COMPILER ${AFL_C_COMPILER})
    set(CMAKE_CXX_COMPILER ${AFL_CXX_COMPILER})
else ()
    message(ERROR "AFL compiler not found")
endif ()
