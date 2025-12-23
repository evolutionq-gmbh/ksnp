
#include <array>
#include <cstddef>
#include <cstring>

#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>
#include <json-c/json_object.h>
#include <json-c/json_types.h>

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

char const test_string[] = "abcdefghijkl";

json_obj test_extension{[] {
    auto obj = json_object_new_object();
    json_object_object_add(obj, "myval", json_object_new_int(42));
    return obj;
}()};

ksnp_stream_open_params req_params{
    .stream_id           = {},
    .source              = {.sae = nullptr, .network = "source-net"},
    .destination         = {.sae = "target SAE", .network = nullptr},
    .chunk_size          = 32,
    .capacity            = 1024,
    .min_bps             = {.bits = 256, .seconds = 0},
    .max_bps             = {.bits = 0, .seconds = 0},
    .ttl                 = 30,
    .provision_size      = 0,
    .extensions          = nullptr,
    .required_extensions = *test_extension,
};

ksnp_stream_open_params req_params_minimal{
    .stream_id           = {},
    .source              = {.sae = nullptr, .network = nullptr},
    .destination         = {.sae = "target SAE", .network = nullptr},
    .chunk_size          = 0,
    .capacity            = 0,
    .min_bps             = {.bits = 0, .seconds = 0},
    .max_bps             = {.bits = 0, .seconds = 0},
    .ttl                 = 0,
    .provision_size      = 0,
    .extensions          = nullptr,
    .required_extensions = nullptr,
};

ksnp_stream_accepted_params acc_params{
    .stream_id      = {},
    .chunk_size     = 0,
    .position       = 0,
    .max_key_delay  = 0,
    .min_bps        = ksnp_rate{.bits = 1, .seconds = 0},
    .provision_size = 0,
    .extensions     = *test_extension,
};

uint16_t supported_chunk_sizes[] = {8, 16, 32, 17};

ksnp_stream_qos_params qos_params{
    .chunk_size     = {.type = ksnp_qos_type::KSNP_QOS_LIST,
                       .list = {.values = supported_chunk_sizes, .count = std::size(supported_chunk_sizes)}  },
    .min_bps        = {.type  = ksnp_qos_type::KSNP_QOS_RANGE,
                       .range = {.min = {.bits = 4, .seconds = 5}, .max = {.bits = 256 * 1024, .seconds = 0}}},
    .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE,   .none = 0                                     },
    .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NULL,   .none = 0                                     },
    .extensions     = nullptr,
};

ksnp::message_t const good_messages[] = {
    ksnp_msg_error{.code = ksnp_error_code{0xFFFF0000}},
    ksnp_msg_version{.minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                   .maximum_version = ksnp_protocol_version::PROTOCOL_V1},
    ksnp_msg_open_stream{.parameters = &req_params},
    ksnp_msg_open_stream{.parameters = &req_params_minimal},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
                   .parameters = ksnp_stream_reply_params{.reply = &acc_params},
                   .message    = nullptr},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER,
                   .parameters = ksnp_stream_reply_params{.qos = &qos_params},
                   .message    = test_string},
    ksnp_msg_close_stream{},
    ksnp_msg_close_stream_reply{},
    ksnp_msg_close_stream_notify{.code = ksnp_status_code::KSNP_STATUS_SUCCESS, .message = nullptr},
    ksnp_msg_close_stream_notify{.code    = ksnp_status_code::KSNP_STATUS_NOTIFY_DUE_TO_PEER,
                   .message = "peer closing stream"},
    ksnp_msg_suspend_stream{.timeout = 30},
    ksnp_msg_suspend_stream_reply{.code = ksnp_status_code::KSNP_STATUS_SUCCESS, .timeout = 30, .message = nullptr},
    ksnp_msg_suspend_stream_reply{.code    = ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER,
                   .timeout = 10,
                   .message = "requested timeout too short"},
    ksnp_msg_suspend_stream_notify{.code = ksnp_status_code::KSNP_STATUS_NOTIFY_DUE_TO_PEER, .timeout = 60},
    ksnp_msg_keep_alive_stream{
                   .key_stream_id =
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}},
    ksnp_msg_keep_alive_stream_reply{.code = ksnp_status_code::KSNP_STATUS_SUCCESS, .message = nullptr},
    ksnp_msg_keep_alive_stream_reply{.code    = ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED,
                   .message = "I'm afraid I can't do that"},
    ksnp_msg_capacity_notify{.additional_capacity = 32},
    ksnp_msg_key_data_notify{.key_data   = ksnp_data{.data = reinterpret_cast<unsigned char const *>(test_string),
                                                     .len  = std::size(test_string)},
                   .parameters = nullptr},
    ksnp_msg_key_data_notify{.key_data   = ksnp_data{.data = reinterpret_cast<unsigned char const *>(test_string),
                                                     .len  = std::size(test_string)},
                   .parameters = *test_extension},
};

ksnp_stream_open_params req_params_bad_dest{
    .stream_id           = {},
    .source              = {.sae = nullptr, .network = nullptr},
    .destination         = {.sae = nullptr, .network = nullptr},
    .chunk_size          = 0,
    .capacity            = 0,
    .min_bps             = {.bits = 0, .seconds = 0},
    .max_bps             = {.bits = 0, .seconds = 0},
    .ttl                 = 0,
    .provision_size      = 0,
    .extensions          = nullptr,
    .required_extensions = nullptr,
};

ksnp_stream_open_params req_params_bad_prov_chunk{
    .stream_id           = {},
    .source              = {.sae = nullptr, .network = nullptr},
    .destination         = {.sae = "target SAE", .network = nullptr},
    .chunk_size          = 11,
    .capacity            = 0,
    .min_bps             = {.bits = 0, .seconds = 0},
    .max_bps             = {.bits = 0, .seconds = 0},
    .ttl                 = 0,
    .provision_size      = 10,
    .extensions          = nullptr,
    .required_extensions = nullptr,
};

ksnp_stream_accepted_params acc_params_missing_bps{
    .stream_id      = {},
    .chunk_size     = 0,
    .position       = 0,
    .max_key_delay  = 0,
    .min_bps        = ksnp_rate{.bits = 0, .seconds = 0},
    .provision_size = 0,
    .extensions     = *test_extension,
};

ksnp_stream_accepted_params acc_params_bad_chunk_size{
    .stream_id      = {},
    .chunk_size     = 0x8001,
    .position       = 0,
    .max_key_delay  = 0,
    .min_bps        = ksnp_rate{.bits = 1, .seconds = 0},
    .provision_size = 0,
    .extensions     = *test_extension,
};

ksnp_stream_accepted_params acc_params_bad_prov_chunk{
    .stream_id      = {},
    .chunk_size     = 7,
    .position       = 0,
    .max_key_delay  = 0,
    .min_bps        = ksnp_rate{.bits = 1, .seconds = 0},
    .provision_size = 6,
    .extensions     = *test_extension,
};

ksnp_stream_qos_params qos_params_bad_int_range{
    .chunk_size     = {.type = ksnp_qos_type::KSNP_QOS_RANGE, .range = {.min = 0xEB, .max = 0xEA}},
    .min_bps        = {.type = ksnp_qos_type::KSNP_QOS_NONE,  .none = 0                          },
    .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE,  .none = 0                          },
    .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NONE,  .none = 0                          },
    .extensions     = nullptr,
};

ksnp_stream_qos_params qos_params_bad_rate_range{
    .chunk_size     = {.type = ksnp_qos_type::KSNP_QOS_NONE,   .none = 0                            },
    .min_bps        = {.type  = ksnp_qos_type::KSNP_QOS_RANGE,
                       .range = {.min = {.bits = 2, .seconds = 0}, .max = {.bits = 3, .seconds = 2}}},
    .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE,   .none = 0                            },
    .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NONE,   .none = 0                            },
    .extensions     = nullptr,
};

ksnp_stream_qos_params qos_params_bad_chunk_range{
    .chunk_size     = {.type = ksnp_qos_type::KSNP_QOS_RANGE, .range = {.min = 16, .max = 0x8001}},
    .min_bps        = {.type = ksnp_qos_type::KSNP_QOS_NONE,  .none = 0                          },
    .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE,  .none = 0                          },
    .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NONE,  .none = 0                          },
    .extensions     = nullptr,
};

uint16_t supported_chunk_sizes_bad[] = {8, 16, 32, 17, 0x7FF, 0xF000, 511, 64};

ksnp_stream_qos_params qos_params_bad_chunk_list{
    .chunk_size     = {.type = ksnp_qos_type::KSNP_QOS_LIST,
                       .list = {.values = supported_chunk_sizes_bad, .count = std::size(supported_chunk_sizes_bad)}},
    .min_bps        = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0                                             },
    .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0                                             },
    .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0                                             },
    .extensions     = nullptr,
};

ksnp::message_t const bad_messages_rt[] = {
    ksnp_msg_version{.minimum_version = static_cast<ksnp_protocol_version>(2),
                     .maximum_version = ksnp_protocol_version::PROTOCOL_V1},
    ksnp_msg_version{.minimum_version = static_cast<ksnp_protocol_version>(0xFF),
                     .maximum_version = ksnp_protocol_version::PROTOCOL_V1},
    ksnp_msg_open_stream{.parameters = &req_params_bad_dest},
    ksnp_msg_open_stream{.parameters = &req_params_bad_prov_chunk},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
                     .parameters = ksnp_stream_reply_params{.reply = &acc_params_bad_chunk_size},
                     .message    = nullptr},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
                     .parameters = ksnp_stream_reply_params{.reply = &acc_params_bad_prov_chunk},
                     .message    = nullptr},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER,
                     .parameters = ksnp_stream_reply_params{.qos = &qos_params_bad_int_range},
                     .message    = nullptr},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER,
                     .parameters = ksnp_stream_reply_params{.qos = &qos_params_bad_rate_range},
                     .message    = nullptr},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER,
                     .parameters = ksnp_stream_reply_params{.qos = &qos_params_bad_chunk_range},
                     .message    = nullptr},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER,
                     .parameters = ksnp_stream_reply_params{.qos = &qos_params_bad_chunk_list},
                     .message    = nullptr},
};

std::string const large_string(0xFFFF, '*');

ksnp_stream_open_params req_params_too_large{
    .stream_id           = {},
    .source              = {.sae = nullptr, .network = nullptr},
    .destination         = {.sae = large_string.c_str(), .network = nullptr},
    .chunk_size          = 0,
    .capacity            = 0,
    .min_bps             = {.bits = 0, .seconds = 0},
    .max_bps             = {.bits = 0, .seconds = 0},
    .ttl                 = 0,
    .provision_size      = 0,
    .extensions          = nullptr,
    .required_extensions = nullptr,
};

ksnp::message_t const bad_messages_ser[] = {
    ksnp_msg_open_stream{.parameters = nullptr},
    ksnp_msg_open_stream{.parameters = &req_params_too_large},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
                         .parameters = ksnp_stream_reply_params{.reply = nullptr},
                         .message    = nullptr},
    ksnp_msg_open_stream_reply{.code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
                         .parameters = ksnp_stream_reply_params{.reply = &acc_params},
                         .message    = test_string},
    ksnp_msg_close_stream_notify{.code = ksnp_status_code::KSNP_STATUS_SUCCESS, .message = test_string},
    ksnp_msg_suspend_stream_reply{.code = ksnp_status_code::KSNP_STATUS_SUCCESS, .timeout = 10, .message = test_string},
    ksnp_msg_keep_alive_stream_reply{.code = ksnp_status_code::KSNP_STATUS_SUCCESS, .message = test_string},
};

const_data const bad_parser_input[] = {
    // Invalid message size: smaller than header size
    {"\x00\x00\x00\x03",                                                                                               4 },
    // Error message too short
    {"\x00\x00\x00\x04",                                                                                               4 },
    // Error message too long
    {"\x00\x00\x00\x09\x00\x00\x00\x00\x00",                                                                           9 },
    // Version message too short
    {"\x00\x01\x00\x05\x01",                                                                                           5 },
    // Version message too long
    {"\x00\x01\x00\x07\x01\x02\x03",                                                                                   7 },
    // OpenStream message; missing JSON
    {"\x00\x02\x00\x04",                                                                                               4 },
    // OpenStream message; invalid JSON: missing brace
    {"\x00\x02\x00\x1E{\"destination\":{\"sae\":\"x\"}",                                                               30},
    // OpenStream message; bad top level JSON object type
    {"\x00\x02\x00\x08null",                                                                                           8 },
    // OpenStream message; unknown JSON key
    {"\x00\x02\x00\x2A{\"destination\":{\"sae\":\"x\"},\"ttt\":1000}",                                                 42},
    // OpenStream message; bad stream_id: missing dash
    {"\x00\x02\x00\x55{\"destination\":{\"sae\":\"x\"},\"key-stream-id\":\"12345678-12341234-1234-123456789ABC\"}",    85},
    // OpenStream message; bad stream_id: missing byte
    {"\x00\x02\x00\x54{\"destination\":{\"sae\":\"x\"},\"key-stream-id\":\"12345678-1234-1234-1234-123456789A\"}",     84},
    // OpenStream message; bad stream_id: extra byte
    {"\x00\x02\x00\x58{\"destination\":{\"sae\":\"x\"},\"key-stream-id\":\"12345678-1234-1234-1234-123456789ABCDE\"}",
     88                                                                                                                  },
    // OpenStream message; bad chunk_size: bad type
    {"\x00\x02\x00\x31{\"destination\":{\"sae\":\"x\"},\"chunk-size\":null}",                                          49},
    // OpenStream message; bad chunk_size: bad type
    {"\x00\x02\x00\x31{\"destination\":{\"sae\":\"x\"},\"chunk-size\":\"16\"}",                                        49},
    // OpenStream message; bad capacity: value exceeds u32 limit
    {"\x00\x02\x00\x35{\"destination\":{\"sae\":\"x\"},\"capacity\":4294967296}",                                      53},
    // OpenStream message; extra data after JSON
    {"\x00\x02\x00\x21{\"destination\":{\"sae\":\"x\"}}{}",                                                            33},
    // OpenStream message; unknown key in address subobject
    {"\x00\x02\x00\x25{\"destination\":{\"sae\":\"x\",\"x\":1}}",                                                      37},
    // OpenStream message; unknown key in rate subobject
    {"\x00\x02\x00\x3A{\"destination\":{\"sae\":\"x\"},\"min-bps\":{\"bits\":1,\"x\":1}}",                             58},
    // OpenStreamReply message; success with missing JSON
    {"\x00\x03\x00\x0A\x00\x00\x00\x00\x00\x00",                                                                       10},
    // OpenStreamReply message; error with missing JSON
    {"\x00\x03\x00\x1E\x00\x00\x00\x01\x00\x00something went wrong",                                                   30},
    // OpenStreamReply message; error with JSON length exceeding remaining message length
    {"\x00\x03\x00\x0C\x00\x00\x00\x01\x00\x03{}",                                                                     12},
    // OpenStreamReply message; success code with QoS parameter
    {"\x00\x03\x00\x3B\x00\x00\x00\x00\x00\x31{\"min-bps\":{\"min\":{\"bits\":1},\"max\":{\"bits\":256}}}",            59},
    // OpenStreamReply message; error code with non-QoS parameter
    {"\x00\x03\x00\x1B\x00\x00\x00\x01\x00\x11{\"chunk-size\":16}",                                                    27},
    // OpenStreamReply message; QoS parameter exceeding u32 limit
    {"\x00\x03\x00\x25\x00\x00\x00\x01\x00\x1B{\"chunk-size\":[4294967296]}",                                          37},
    // OpenStreamReply message; QoS parameter with bad type
    {"\x00\x03\x00\x1F\x00\x00\x00\x01\x00\x15{\"chunk-size\":[\"16\"]}",                                              31},
    // OpenStreamReply message; QoS parameter with unknown key
    {"\x00\x03\x00\x14\x00\x00\x00\x01\x00\x0A{\"x\":null}",                                                           20},
    // OpenStreamReply message; QoS parameter with unknown key in range
    {"\x00\x03\x00\x3F\x00\x00\x00\x01\x00\x35{\"min-bps\":{\"min\":{\"bits\":1},\"max\":{\"bits\":2},\"x\":1}}",      63},
    // OpenStreamReply message; QoS parameter with unknown key in range subobject
    {"\x00\x03\x00\x3F\x00\x00\x00\x01\x00\x35{\"min-bps\":{\"min\":{\"bits\":1,\"x\":1},\"max\":{\"bits\":2}}}",      63},
    // OpenStreamReply message; QoS parameter with unknown key in list subobject
    {"\x00\x03\x00\x28\x00\x00\x00\x01\x00\x1E{\"min-bps\":[{\"bits\":1,\"x\":1}]}",                                   40},
    // CloseStream message with extra data
    {"\x00\x04\x00\x05\x00",                                                                                           5 },
    // CloseStreamReply message with extra data
    {"\x00\x05\x00\x05\x00",                                                                                           5 },
    // CloseStreamNotify message with insufficient data
    {"\x00\x06\x00\x07\x00\x00\x00",                                                                                   7 },
    // SuspendStream message with insufficient data
    {"\x00\x07\x00\x07\x00\x00\x00",                                                                                   7 },
    // SuspendStream message with extra data
    {"\x00\x07\x00\x09\x00\x00\x00\x00\x00",                                                                           9 },
    // SuspendStreamReply message with insufficient data
    {"\x00\x08\x00\x0B\x00\x00\x00\x00\x00\x00\x00",                                                                   11},
    // SuspendStreamReply message success code with extra data
    {"\x00\x08\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00x",                                                              13},
    // SuspendStreamNotify message with insufficient data
    {"\x00\x09\x00\x0B\x00\x00\x00\x00\x00\x00\x00",                                                                   11},
    // SuspendStreamNotify message with extra data
    {"\x00\x09\x00\x0D\x00\x00\x00\x01\x00\x00\x00\x00\x00",                                                           13},
    // KeepAlive message with insufficient data
    {"\x00\x0A\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",                                   19},
    // KeepAlive message with extra data
    {"\x00\x0A\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",                           21},
    // KeepAliveReply message with insufficient data
    {"\x00\x0B\x00\x0B\x00\x00\x00\x00\x00\x00\x00",                                                                   11},
    // KeepAliveReply message success code with extra data
    {"\x00\x0B\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00x",                                                              13},
    // CapacityNotify message with insufficient data
    {"\x00\x0C\x00\x07\x00\x00\x00",                                                                                   7 },
    // CapacityNotify message with extra data
    {"\x00\x0C\x00\x09\x00\x00\x00\x00\x00",                                                                           9 },
    // KeyDataNotify message with insufficient data
    {"\x00\x0D\x00\x06\x00\x01",                                                                                       6 },
    // KeyDataNotify message with extra data (which isn't valid JSON)
    {"\x00\x0D\x00\x0A\x00\x03\xF4\x13\x7A{",                                                                          10},
};

}  // namespace

BOOST_DATA_TEST_CASE(test_serde_rt, boost::unit_test::data::make(good_messages), message)
{
    message_context_t                      ctx;
    std::array<unsigned char, BUFFER_SIZE> write_mem{};
    std::span<unsigned char>               write_buffer = {write_mem};

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

BOOST_DATA_TEST_CASE(test_serde_rt_bad_input, boost::unit_test::data::make(bad_messages_rt), message)
{
    message_context_t                      ctx;
    std::array<unsigned char, BUFFER_SIZE> write_mem{};
    std::span<unsigned char>               write_buffer = {write_mem};

    BOOST_REQUIRE(ctx.want_read());
    BOOST_REQUIRE(!ctx.want_write());

    auto raw_msg = ksnp::into_message(message);
    ctx.write_message(&raw_msg);
    auto written = ctx.write_data(write_buffer);
    BOOST_REQUIRE(ctx.read_data(write_buffer.first(written)) == written);

    BOOST_CHECK_THROW(ctx.next_event(), ksnp::protocol_exception);
}

BOOST_DATA_TEST_CASE(test_serializer_bad_input, boost::unit_test::data::make(bad_messages_ser), message)
{
    message_context_t ctx;

    BOOST_REQUIRE(ctx.want_read());
    BOOST_REQUIRE(!ctx.want_write());

    auto raw_msg = ksnp::into_message(message);
    BOOST_CHECK_THROW(ctx.write_message(&raw_msg), ksnp_exception);
}

BOOST_DATA_TEST_CASE(test_parser_bad_input, boost::unit_test::data::make(bad_parser_input), input)
{
    message_context_t ctx;

    BOOST_REQUIRE(ctx.read_data(input) == input.size());

    BOOST_CHECK_THROW(ctx.next_event(), ksnp::protocol_exception);
}

BOOST_AUTO_TEST_SUITE_END()
