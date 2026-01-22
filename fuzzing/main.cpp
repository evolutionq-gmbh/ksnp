#include <cstdio>
#include <unistd.h>

#include "ksnp/messages.h"
#include "ksnp/serde.h"


namespace {
    constexpr size_t loop_count = 10000;
    constexpr size_t input_min_len = 4;

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

__AFL_FUZZ_INIT();

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    // __AFL_FUZZ_TESTCASE_BUF must be after __AFL_INIT and before __AFL_LOOP!
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(loop_count)) {
        // __AFL_FUZZ_TESTCASE_LEN must not be used directly in a call!
        int len = __AFL_FUZZ_TESTCASE_LEN;

        if (static_cast<size_t>(len) < input_min_len) {
            // Skip if length is too short for a useful test.
            continue;
        }

        // Setup
        struct ksnp_message_context *ctx;
        ksnp_message_context_create(&ctx);

        // Fuzz the parser
        size_t buf_len = len;
        auto err = ksnp_message_context_read_data(ctx, buf, &buf_len);
        if (err == ksnp_error::KSNP_E_NO_ERROR) {
            struct ksnp_message msg;
            struct ksnp_protocol_error err;
            (void) ksnp_message_context_next_message(ctx, &msg, &err);
        }

        // Reset
        ksnp_message_context_destroy(ctx);
    }

    return 0;
}
