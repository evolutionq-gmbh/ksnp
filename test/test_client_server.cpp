#include <cstddef>
#include <cstring>
#include <limits>
#include <optional>

#include <boost/test/unit_test.hpp>
#include <json_object.h>
#include <json_types.h>

#include "common.hpp"
#include "helpers.hpp"
#include "ksnp/client.h"
#include "ksnp/serde.h"
#include "ksnp/server.h"
#include "ksnp/types.h"
#include "test_helpers.hpp"

static size_t const BUFFER_SIZE = 1024;

using json_obj = ksnp::unique_obj<json_object *, json_object_put>;

class connection
{
    std::unique_ptr<message_context_t> client_serde;
    client_obj                         client_conn;
    buffer                             write_buffer_client;
    std::unique_ptr<message_context_t> server_serde;
    server_obj                         server_conn;
    buffer                             write_buffer_server;

public:
    connection()
        : client_serde(new message_context_t)
        , client_conn(*this->client_serde)
        , write_buffer_client(BUFFER_SIZE)
        , server_serde(new message_context_t)
        , server_conn(*this->server_serde)
        , write_buffer_server(BUFFER_SIZE)
    {}

    void complete_io()
    {
        bool io_performed = true;
        while (io_performed) {
            io_performed = false;
            if (client_conn.want_write()) {
                auto written = client_conn.write_data(write_buffer_client.remaining());
                write_buffer_client.fill(written);
                io_performed |= written > 0;
            }
            if (!write_buffer_client.empty()) {
                auto written = server_conn.read_data(write_buffer_client.filled());
                write_buffer_client.consume(written);
                io_performed |= written > 0;
            }
            if (server_conn.want_write()) {
                auto written = server_conn.write_data(write_buffer_server.remaining());
                write_buffer_server.fill(written);
                io_performed |= written > 0;
            }
            if (!write_buffer_server.empty()) {
                auto written = client_conn.read_data(write_buffer_server.filled());
                write_buffer_server.consume(written);
                io_performed |= written > 0;
            }
        }
    }

    void complete_handshake()
    {
        this->complete_io();
        this->client().next_event();
        this->server().next_event();
    }

    auto client() -> client_obj &
    {
        return this->client_conn;
    }

    auto server() -> server_obj &
    {
        return this->server_conn;
    }

    auto client_message_context() -> message_context_t &
    {
        return *this->client_serde;
    }

    auto server_message_context() -> message_context_t &
    {
        return *this->server_serde;
    }
};

BOOST_AUTO_TEST_SUITE(test_client_server)

/**
 * Connections immediately generate handshake events.
 */
BOOST_AUTO_TEST_CASE(test_connection_handshake)
{
    connection conn;

    // Handshake starts immediately
    conn.complete_io();

    BOOST_CHECK(conn.client().next_event()
                == ksnp::client_event{::ksnp_client_event_handshake{.protocol = ksnp_protocol_version::PROTOCOL_V1}});
    BOOST_CHECK(conn.server().next_event()
                == ksnp::server_event{::ksnp_server_event_handshake{.protocol = ksnp_protocol_version::PROTOCOL_V1}});

    // Additional version messages trigger an error on the other side after
    // processing.
    ksnp_message ver_msg = ksnp::into_message(ksnp_msg_version{
        .minimum_version = ksnp_protocol_version::PROTOCOL_V1,
        .maximum_version = ksnp_protocol_version::PROTOCOL_V1,
    });
    BOOST_CHECK_NO_THROW(conn.client_message_context().write_message(&ver_msg));
    BOOST_CHECK_NO_THROW(conn.server_message_context().write_message(&ver_msg));
    conn.complete_io();

    auto client_event = ksnp::client_event{
        ksnp_client_event_error{
                                .code        = ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE,
                                .description = nullptr,
                                }
    };
    auto server_event = ksnp::server_event{
        ksnp_server_event_error{
                                .code        = ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE,
                                .description = nullptr,
                                .stream      = nullptr,
                                }
    };
    BOOST_CHECK(conn.client().next_event() == client_event);
    BOOST_CHECK(conn.server().next_event() == server_event);
    conn.complete_io();
}

/**
 * Injecting an error should result in an API error. It should not generate a
 * return error.
 */
BOOST_AUTO_TEST_CASE(test_connection_error)
{
    connection conn;

    conn.complete_handshake();

    ksnp_message err_msg = ksnp::into_message(ksnp_msg_error{
        .code = ksnp_error_code::KSNP_PROT_E_UNKNOWN_ERROR,
    });
    BOOST_CHECK_NO_THROW(conn.client_message_context().write_message(&err_msg));

    conn.complete_io();
    auto server_event = ksnp::server_event{
        ksnp_server_event_error{
                                .code        = ksnp_error_code::KSNP_PROT_E_UNKNOWN_ERROR,
                                .description = nullptr,
                                .stream      = nullptr,
                                }
    };
    BOOST_CHECK(conn.server().next_event() == server_event);

    conn.complete_io();
    BOOST_CHECK(conn.client().next_event() == std::nullopt);
}

/**
 * Sending an unexpected message should result in an error event, and return an
 * error message triggering a client API error.
 */
BOOST_AUTO_TEST_CASE(test_connection_wrong_message)
{
    connection conn;

    conn.complete_handshake();

    ksnp_message err_msg = ksnp::into_message(ksnp_msg_close_stream_notify{
        .code    = ksnp_status_code::KSNP_STATUS_SUCCESS,
        .message = nullptr,
    });
    BOOST_CHECK_NO_THROW(conn.client_message_context().write_message(&err_msg));

    conn.complete_io();
    auto client_event = ksnp::client_event{
        ksnp_client_event_error{
                                .code        = ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE,
                                .description = nullptr,
                                }
    };
    auto server_event = ksnp::server_event{
        ::ksnp_server_event_error{
                                  .code        = ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE,
                                  .description = nullptr,
                                  .stream      = nullptr,
                                  }
    };
    BOOST_CHECK(conn.server().next_event() == server_event);

    // Receiving an error means API error.
    conn.complete_io();
    BOOST_CHECK(conn.client().next_event() == client_event);
}

BOOST_AUTO_TEST_CASE(test_connection_server_events)
{
    connection conn;

    conn.complete_handshake();

    ksnp_stream_open_params params{};
    params.destination = ksnp_address{.sae = "target", .network = nullptr};

    BOOST_CHECK_NO_THROW(conn.client().open_stream(params));
    conn.complete_io();
    BOOST_CHECK(conn.server().next_event()
                == ksnp::server_event{::ksnp_server_event_open_stream{.parameters = &params}});

    // Cannot continue processing until the event is handled
    BOOST_CHECK_EXCEPTION(conn.server().next_event(), ksnp_exception, [](ksnp_exception const &exc) -> bool {
        return exc.error() == ksnp_error::KSNP_E_INVALID_OPERATION;
    });
    // Cannot perform a different action
    BOOST_CHECK_EXCEPTION(conn.server().keep_alive_fail(ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED, nullptr),
                          ksnp_exception,
                          [](ksnp_exception const &exc) -> bool {
                              return exc.error() == ksnp_error::KSNP_E_INVALID_OPERATION;
                          });

    // Send fail and wait for client event
    BOOST_CHECK_NO_THROW(
        conn.server().open_stream_fail(ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED, nullptr, nullptr));
    conn.complete_io();
    auto event = ::ksnp_client_event_stream_open{
        .code       = ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED,
        .parameters = ksnp_stream_reply_params{.qos = nullptr},
        .message    = nullptr,
    };
    BOOST_CHECK(conn.client().next_event() == ksnp::client_event{event});

    // Sending fail again should fail
    BOOST_CHECK_EXCEPTION(
        conn.server().open_stream_fail(ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED, nullptr, nullptr),
        ksnp_exception,
        [](ksnp_exception const &exc) -> bool {
            return exc.error() == ksnp_error::KSNP_E_INVALID_OPERATION;
        });
}

BOOST_AUTO_TEST_CASE(test_connection_client_over_capacity)
{
    connection conn;

    conn.complete_handshake();

    ksnp_stream_open_params params{};
    params.chunk_size  = CHUNK_SIZE;
    params.destination = ksnp_address{.sae = "target", .network = nullptr};
    params.capacity    = std::numeric_limits<uint32_t>::max();
    params.min_bps     = ksnp_rate{.bits = 1, .seconds = 0};

    BOOST_CHECK_NO_THROW(conn.client().open_stream(params));

    conn.complete_io();
    BOOST_CHECK(conn.server().next_event()
                == ksnp::server_event{::ksnp_server_event_open_stream{.parameters = &params}});

    // Send accept
    ksnp::unique_obj<struct ksnp_stream *, ksnp_simple_stream_destroy> stream;
    check_error(ksnp_simple_stream_create(&stream.get(), params.chunk_size));
    ksnp_stream_accepted_params accept_params{};
    accept_params.min_bps = ksnp_rate{.bits = 1, .seconds = 0};
    BOOST_CHECK_NO_THROW(conn.server().open_stream_ok(stream.get(), accept_params));
    conn.complete_io();

    // Check accept event
    auto event = ::ksnp_client_event_stream_open{
        .code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
        .parameters = ksnp_stream_reply_params{.reply = &accept_params},
        .message    = nullptr,
    };
    BOOST_CHECK(conn.client().next_event() == ksnp::client_event{event});

    // Any additional capacity must be rejected
    BOOST_CHECK_EXCEPTION(conn.client().add_capacity(1), ksnp_exception, [](auto const &exc) -> bool {
        return exc.error() == ksnp_error::KSNP_E_INVALID_ARGUMENT;
    });
    auto raw_message = ksnp::into_message(ksnp::message_t{::ksnp_msg_capacity_notify{.additional_capacity = 1}});
    conn.client_message_context().write_message(&raw_message);
    conn.complete_io();
    auto server_event = ksnp::server_event{
        ::ksnp_server_event_error{
                                  .code        = ksnp_error_code::KSNP_PROT_E_EXCESSIVE_CAPACITY,
                                  .description = nullptr,
                                  .stream      = nullptr,
                                  }
    };
    auto client_event = ksnp::client_event{
        ksnp_client_event_error{
                                .code        = ksnp_error_code::KSNP_PROT_E_EXCESSIVE_CAPACITY,
                                .description = nullptr,
                                }
    };
    BOOST_CHECK(conn.server().next_event() == server_event);
    conn.complete_io();
    // The server must have replied with an error
    BOOST_CHECK(conn.client().next_event() == client_event);
}

/**
 * Open a stream and ensure key data is sent in exactly multiples of the chunk
 * size.
 */
BOOST_AUTO_TEST_CASE(test_connection_client_chunk_size)
{
    connection conn;

    conn.complete_handshake();

    ksnp_stream_open_params params{};
    params.chunk_size  = CHUNK_SIZE;
    params.destination = ksnp_address{.sae = "target", .network = nullptr};
    params.capacity    = std::numeric_limits<uint32_t>::max();
    params.min_bps     = ksnp_rate{.bits = 1, .seconds = 0};

    BOOST_CHECK_NO_THROW(conn.client().open_stream(params));
    conn.complete_io();
    BOOST_CHECK(conn.server().next_event()
                == ksnp::server_event{::ksnp_server_event_open_stream{.parameters = &params}});

    // Send accept
    ksnp::unique_obj<struct ksnp_stream *, ksnp_simple_stream_destroy> stream;
    check_error(ksnp_simple_stream_create(&stream.get(), params.chunk_size));
    ksnp_stream_accepted_params accept_params{};
    accept_params.min_bps = ksnp_rate{.bits = 1, .seconds = 0};
    BOOST_CHECK_NO_THROW(conn.server().open_stream_ok(stream.get(), accept_params));
    conn.complete_io();

    // Check accept event
    auto event = ::ksnp_client_event_stream_open{
        .code       = ksnp_status_code::KSNP_STATUS_SUCCESS,
        .parameters = ksnp_stream_reply_params{.reply = &accept_params},
        .message    = nullptr,
    };
    BOOST_CHECK(conn.client().next_event() == ksnp::client_event{event});

    // Derive key data from a fixed buffer
    std::vector<unsigned char> key_source(BUFFER_SIZE, 0x44);
    ksnp_data                  key_data{.data = key_source.data(), .len = 0};

    // Nothing to write on insufficent key data
    key_data.len = CHUNK_SIZE - 1;
    check_error(ksnp_simple_stream_add_key_data(*stream, key_data));
    BOOST_CHECK(!conn.server().want_write());

    // Write a single chunk
    key_data.len = 1;
    check_error(ksnp_simple_stream_add_key_data(*stream, key_data));
    BOOST_CHECK(conn.server().want_write());
    conn.complete_io();
    auto key_event = ::ksnp_client_event_key_data{
        .key_data = ksnp_data{.data = key_source.data(), .len = CHUNK_SIZE},
          .parameters = nullptr
    };
    BOOST_CHECK(conn.client().next_event() == ksnp::client_event{key_event});

    // Write multiple and partial chunk, expect multiple complete chunks
    key_data.len = (2 * CHUNK_SIZE) + (CHUNK_SIZE / 2);
    check_error(ksnp_simple_stream_add_key_data(*stream, key_data));
    conn.complete_io();
    key_event.key_data.len = static_cast<size_t>(CHUNK_SIZE);
    BOOST_CHECK(conn.client().next_event() == ksnp::client_event{key_event});
    conn.complete_io();
    BOOST_CHECK(conn.client().next_event() == ksnp::client_event{key_event});

    // Finalize last chunk
    key_data.len = CHUNK_SIZE - (CHUNK_SIZE / 2);
    check_error(ksnp_simple_stream_add_key_data(*stream, key_data));
    conn.complete_io();
    key_event.key_data.len = static_cast<size_t>(CHUNK_SIZE);
    BOOST_CHECK(conn.client().next_event() == ksnp::client_event{key_event});

    // Insert non chunk-sized key data into stream, expect protocol error
    auto chunk_msg = ksnp::into_message(ksnp_msg_key_data_notify{
        .key_data = ksnp_data{.data = key_source.data(), .len = CHUNK_SIZE + 1},
          .parameters = nullptr
    });
    conn.server_message_context().write_message(&chunk_msg);
    conn.complete_io();

    auto client_event = ksnp::client_event{
        ::ksnp_client_event_error{
                                  .code        = ksnp_error_code::KSNP_PROT_E_INVALID_CHUNK,
                                  .description = nullptr,
                                  }
    };
    auto server_event = ksnp::server_event{
        ::ksnp_server_event_error{
                                  .code        = ksnp_error_code::KSNP_PROT_E_INVALID_CHUNK,
                                  .description = nullptr,
                                  .stream      = nullptr,
                                  }
    };
    BOOST_CHECK(conn.client().next_event() == client_event);
    conn.complete_io();

    BOOST_CHECK(conn.server().next_event() == server_event);
}

BOOST_AUTO_TEST_SUITE_END()
