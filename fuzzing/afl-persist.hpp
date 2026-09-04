#pragma once
#include <unistd.h>

namespace {
    constexpr size_t loop_count = 10000;
    constexpr size_t input_min_len = 2;

#ifndef __AFL_FUZZ_TESTCASE_LEN
#pragma message "Emulating AFL persistent mode"
    constexpr size_t fuzz_max_len = 1024000;

    ssize_t fuzz_len;
    #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
    unsigned char fuzz_buf[fuzz_max_len];
    #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
    #define __AFL_FUZZ_INIT() void sync(void);
    // Ignore loop count in this version of the macro, just read until EOF.
    #define __AFL_LOOP(x) ((fuzz_len = read(STDIN_FILENO, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
    #define __AFL_INIT() sync()
#endif
}
