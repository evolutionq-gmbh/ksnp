#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "afl-persist.hpp"
#include "ksnp/serde.h"
#include "test_helpers.hpp"

namespace {
    constexpr size_t max_buf_len = 1024*1024*50;
}


__AFL_FUZZ_INIT();

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    // __AFL_FUZZ_TESTCASE_BUF must be after __AFL_INIT and before __AFL_LOOP!
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    std::vector<unsigned char> ser_buf;
    ser_buf.resize(max_buf_len);
    std::vector<unsigned char> reser_buf;
    reser_buf.resize(max_buf_len);

    while (__AFL_LOOP(loop_count)) {
        // __AFL_FUZZ_TESTCASE_LEN must not be used directly in a call!
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < input_min_len || len > max_buf_len) {
            // Skip if length is too short for a useful test, or exceedingly
            // long.
            continue;
        }

        // Setup
        struct ksnp_message_context *ctx;
        ksnp_message_context_create(&ctx);
        struct ksnp_message_context *rectx;
        ksnp_message_context_create(&rectx);

        // Fuzz the serializer.
        // We use the parser to produce input for the serializer. Finally, we
        // parse the result again to ensure that the process is consistent. If
        // the parsed data does not match the input, we abort(), which the
        // fuzzer will pick up as a crash.

        // Use parser to create message from fuzzed input. Parsing errors do not
        // cause crashes at this stage, but are ignored.
        struct ksnp_message msg;
        struct ksnp_protocol_error prot_err;
        if (ksnp_message_context_read_data(ctx, buf, &len) != ksnp_error::KSNP_E_NO_ERROR ||
            ksnp_message_context_next_message(ctx, &msg, &prot_err) != ksnp_error::KSNP_E_NO_ERROR) {
            continue;
        }

        // Feed message to serializer.
        switch (ksnp_message_context_write_message(ctx, &msg)) {
        case ksnp_error::KSNP_E_NO_ERROR:
            break;
        case ksnp_error::KSNP_E_INVALID_ARGUMENT:
        case ksnp_error::KSNP_E_INVALID_MESSAGE_TYPE:
            // The fuzzer produced an input with invalid data, like a MSG_NONE
            // type, or an OpenStreamReply with min_bits of 0. Returning an
            // error is correct in this case.
            continue;
        default:
            // Any other error => crash.
            abort();
        }

        // Reparse serialized data. Use a separate context to prevent mixing in
        // leftover data from the first message, and to extend the lifetime of
        // the first message.
        auto *ser_msg = ser_buf.data();
        len = ser_buf.size();
        struct ksnp_message remsg;
        if (ksnp_message_context_write_data(ctx, ser_msg, &len) != ksnp_error::KSNP_E_NO_ERROR ||
            ksnp_message_context_read_data(rectx, ser_msg, &len) != ksnp_error::KSNP_E_NO_ERROR ||
            ksnp_message_context_next_message(rectx, &remsg, &prot_err) != ksnp_error::KSNP_E_NO_ERROR) {
            abort();
        }

        // Check that identical data is produced.
        if (msg != remsg) {
            abort();
        }

        // Reset
        ksnp_message_context_destroy(ctx);
        ksnp_message_context_destroy(rectx);
    }

    return 0;
}
