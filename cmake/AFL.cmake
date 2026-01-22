# Simple toolchain file to use a compiler inserting AFL instrumentation.
# `afl-cc` automatically selects the compiler with the most features.
find_program(AFL_C_COMPILER afl-cc)
find_program(AFL_CXX_COMPILER afl-c++)

if (AFL_C_COMPILER AND AFL_CXX_COMPILER)
    set(CMAKE_C_COMPILER ${AFL_C_COMPILER})
    set(CMAKE_CXX_COMPILER ${AFL_CXX_COMPILER})
else ()
    message(ERROR "AFL compiler not found")
endif ()
