
#include <array>
#include <cstddef>
#include <cstring>

#include <boost/test/unit_test.hpp>
#include <json_object.h>
#include <json_types.h>

#include "common.hpp"
#include "helpers.hpp"
#include "ksnp/types.h"
#include "test_helpers.hpp"

using namespace ksnp;

static size_t const BUFFER_SIZE = 1024;

using json_obj = unique_obj<json_object *, json_object_put>;

BOOST_AUTO_TEST_SUITE(test_message_context)

BOOST_AUTO_TEST_CASE(test_message_context_basics)
{
    message_context_t                      ctx;
    std::array<unsigned char, BUFFER_SIZE> write_buffer{};
    ksnp::message_t const                  version_message = ksnp_msg_version{
                         .minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                         .maximum_version = ksnp_protocol_version::PROTOCOL_V1,
    };
    std::array<unsigned char, 6> const version_data{0, 1, 0, 6, 1, 1};

    // An empty context needs input, has no output
    BOOST_TEST(ctx.want_read());
    BOOST_TEST(!ctx.want_write());
    BOOST_TEST(!ctx.next_event().has_value());
    BOOST_TEST(ctx.write_data({write_buffer}) == 0);

    auto raw_msg = into_message(version_message);
    ctx.write_message(&raw_msg);
    BOOST_TEST(ctx.want_write());
    BOOST_TEST(ctx.write_data({write_buffer}) == 6);
    BOOST_TEST(std::memcmp(write_buffer.data(), version_data.data(), 6) == 0);
    BOOST_TEST(!ctx.want_write());

    // Reading a version message set want_read to false and make the message
    // available.
    BOOST_TEST(ctx.read_data({version_data}) == 6);
    BOOST_TEST(!ctx.want_read());
    auto next_message = ctx.next_event();
    BOOST_REQUIRE(next_message.has_value());
    BOOST_CHECK(*next_message == version_message);

    // Having read the version message, more input should be required, until EOF
    BOOST_TEST(ctx.want_read());
    ctx.read_data({});
    BOOST_TEST(!ctx.want_read());
}

BOOST_AUTO_TEST_CASE(test_message_context_multiple)
{
    message_context_t                      ctx;
    std::array<unsigned char, BUFFER_SIZE> write_buffer{};
    ksnp::message_t const                  version_message = ksnp_msg_version{
                         .minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                         .maximum_version = ksnp_protocol_version::PROTOCOL_V1,
    };
    std::array<unsigned char, 6> const version_data{0, 1, 0, 6, 1, 1};

    // Write three messages
    auto raw_msg = into_message(version_message);
    ctx.write_message(&raw_msg);
    ctx.write_message(&raw_msg);
    ctx.write_message(&raw_msg);
    BOOST_TEST(ctx.want_write());
    BOOST_TEST(ctx.write_data(std::span{write_buffer}.first(6)) == 6);
    BOOST_TEST(ctx.want_write());
    BOOST_TEST(ctx.write_data(std::span{write_buffer}.first(6)) == 6);
    BOOST_TEST(ctx.want_write());
    BOOST_TEST(ctx.write_data(std::span{write_buffer}.first(6)) == 6);

    BOOST_TEST(!ctx.want_write());

    // Read three messages
    BOOST_TEST(ctx.want_read());

    BOOST_TEST(ctx.read_data({version_data}) == 6);
    BOOST_TEST(!ctx.want_read());
    BOOST_TEST(ctx.read_data({version_data}) == 6);
    BOOST_TEST(!ctx.want_read());
    BOOST_TEST(ctx.read_data({version_data}) == 6);
    BOOST_TEST(!ctx.want_read());

    auto next_message = ctx.next_event();
    BOOST_TEST(next_message.has_value());
    BOOST_CHECK(*next_message == version_message);
    BOOST_TEST(!ctx.want_read());

    next_message = ctx.next_event();
    BOOST_TEST(next_message.has_value());
    BOOST_CHECK(*next_message == version_message);
    BOOST_TEST(!ctx.want_read());

    next_message = ctx.next_event();
    BOOST_TEST(next_message.has_value());
    BOOST_CHECK(*next_message == version_message);
    BOOST_TEST(ctx.want_read());
}

BOOST_AUTO_TEST_CASE(test_message_context_partial_read)
{
    message_context_t                  ctx;
    std::array<unsigned char, 6> const version_data{0, 1, 0, 6, 1, 1};

    // Write single bytes, no message should be available until the last one was
    // written.
    for (auto byte: std::span{version_data.begin(), version_data.end() - 1}) {
        BOOST_TEST(ctx.read_data({&byte, 1}) == 1);
        BOOST_TEST(ctx.want_read());
        BOOST_TEST(!ctx.next_event().has_value());
    }

    BOOST_TEST(ctx.read_data({version_data.end() - 1, version_data.end()}) == 1);
    BOOST_TEST(!ctx.want_read());
    BOOST_TEST(ctx.next_event().has_value());
    BOOST_TEST(ctx.want_read());

    // Write a complete and partial message. One should complete immediately,
    // leaving the rest for a later write.
    BOOST_TEST(ctx.read_data({version_data}) == 6);
    BOOST_TEST(ctx.read_data({version_data.begin(), version_data.end() - 1}) == 5);

    BOOST_TEST(ctx.next_event().has_value());
    BOOST_TEST(ctx.want_read());
    BOOST_TEST(!ctx.next_event().has_value());
    BOOST_TEST(ctx.read_data({version_data.end() - 1, version_data.end()}) == 1);
    BOOST_TEST(!ctx.want_read());
    BOOST_TEST(ctx.next_event().has_value());
    BOOST_TEST(ctx.want_read());
}

BOOST_AUTO_TEST_CASE(test_message_context_partial_write)
{
    message_context_t                      ctx;
    std::array<unsigned char, BUFFER_SIZE> write_buffer{};
    ksnp::message_t const                  version_message = ksnp_msg_version{
                         .minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                         .maximum_version = ksnp_protocol_version::PROTOCOL_V1,
    };
    std::array<unsigned char, 6> const version_data{0, 1, 0, 6, 1, 1};

    auto raw_msg = into_message(version_message);

    // Write one message byte for byte, should want writing until complete
    ctx.write_message(&raw_msg);
    for (size_t i = 0; i < version_data.size() - 1; i++) {
        BOOST_TEST(ctx.write_data(std::span{write_buffer}.first(1)) == 1);
        BOOST_TEST(ctx.want_write());
    }

    BOOST_TEST(ctx.write_data(std::span{write_buffer}.first(1)) == 1);
    BOOST_TEST(!ctx.want_write());

    // Write one message partially, add another, both should be complete
    ctx.write_message(&raw_msg);
    BOOST_TEST(ctx.write_data(std::span{write_buffer}.first(version_data.size() / 2)) == version_data.size() / 2);
    BOOST_TEST(ctx.want_write());
    ctx.write_message(&raw_msg);
    BOOST_TEST(ctx.want_write());
    BOOST_TEST(ctx.write_data(std::span{write_buffer}) == (version_data.size() * 2) - (version_data.size() / 2));
    BOOST_TEST(!ctx.want_write());
}

namespace
{

void test_message_rt(message_context_t &ctx, std::span<unsigned char> write_buffer, ksnp::message_t message)
{
    BOOST_REQUIRE(ctx.want_read());
    BOOST_REQUIRE(!ctx.want_write());

    auto raw_msg = ksnp::into_message(message);
    ctx.write_message(&raw_msg);
    auto written = ctx.write_data(write_buffer);
    BOOST_REQUIRE(ctx.read_data(write_buffer.first(written)) == written);

    auto next_message = ctx.next_event();
    BOOST_TEST(next_message.has_value());
    BOOST_CHECK(*next_message == message);
}
}  // namespace

BOOST_AUTO_TEST_CASE(test_serde)
{
    message_context_t                      ctx;
    std::array<unsigned char, BUFFER_SIZE> write_buffer{};
    char const                             test_string[] = "abcdefghijkl";

    json_obj test_extension{json_object_new_object()};
    json_object_object_add(*test_extension, "myval", json_object_new_int(42));

    test_message_rt(ctx, {write_buffer}, ksnp_msg_error{.code = ksnp_error_code{0xFFFF0000}});
    test_message_rt(ctx,
                    {write_buffer},
                    ksnp_msg_version{
                        .minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                        .maximum_version = ksnp_protocol_version::PROTOCOL_V1,
                    });
    test_message_rt(
        ctx,
        {
            write_buffer
    },
        ksnp_msg_key_data_notify{.key_data   = ksnp_data{.data = reinterpret_cast<unsigned char const *>(test_string),
                                                         .len  = sizeof(test_string)},
                                 .parameters = nullptr});
    test_message_rt(
        ctx,
        {
            write_buffer
    },
        ksnp_msg_key_data_notify{.key_data   = ksnp_data{.data = reinterpret_cast<unsigned char const *>(test_string),
                                                         .len  = sizeof(test_string)},
                                 .parameters = *test_extension});

    ksnp_stream_accepted_params params{
        .stream_id      = {},
        .chunk_size     = 0,
        .position       = 0,
        .max_key_delay  = 0,
        .min_bps        = ksnp_rate{.bits = 1, .seconds = 0},
        .provision_size = 0,
        .extensions     = *test_extension,
    };
    test_message_rt(ctx,
                    {write_buffer},
                    ksnp_msg_open_stream_reply{
                        .code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
                        .parameters = ksnp_stream_reply_params{.reply = &params},
                        .message    = nullptr,
                    });
}

BOOST_AUTO_TEST_SUITE_END()