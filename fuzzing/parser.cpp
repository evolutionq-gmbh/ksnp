#include <cstdio>

#include "afl-persist.hpp"
#include "ksnp/messages.h"
#include "ksnp/serde.h"


__AFL_FUZZ_INIT();

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    // __AFL_FUZZ_TESTCASE_BUF must be after __AFL_INIT and before __AFL_LOOP!
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(loop_count)) {
        // __AFL_FUZZ_TESTCASE_LEN must not be used directly in a call!
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < input_min_len) {
            // Skip if length is too short for a useful test.
            continue;
        }

        // Setup
        struct ksnp_message_context *ctx;
        ksnp_message_context_create(&ctx);

        // Fuzz the parser
        auto err = ksnp_message_context_read_data(ctx, buf, &len);
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
