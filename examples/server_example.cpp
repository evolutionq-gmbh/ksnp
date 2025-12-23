/**
 * @file server_example.cpp
 * @author evolutionQ GmbH
 * @copyright Copyright (c) 2025
 *
 * @brief This file, together with the common example source, defines a test
 * server that shows how the key stream protocol API can be used.
 *
 * The @ref server class can be used to interact with a client using some open
 * socket, and internally handles the key stream abstraction by generating
 * all-zero key data.
 */

#include <csignal>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <uuid/uuid.h>
#include <vector>

#include "common.hpp"
#include "helpers.hpp"
#include "ksnp/server.h"
#include "ksnp/types.h"

/**
 * @brief Implementation of a server connection.
 *
 * A server will automatically accept key stream requests. It does not track any
 * state, instead it simply sends mock replies. For key data, it sends all 0
 * data.
 */
class server : private connection_handler<server_obj>
{
public:
    using connection_handler::connection_handler;
    using connection_handler::next_event;

protected:
    auto process_event(server_obj::result_type &event) -> bool override;
};

auto server::process_event(server_obj::result_type &event) -> bool
{
    auto const visitor = ksnp::overloads{
        [this](ksnp_server_event_open_stream &evt) -> bool {
            std::cout << "Open stream request\n";

            if (evt.parameters->chunk_size != 0 && evt.parameters->chunk_size != CHUNK_SIZE) {
                std::array<uint16_t, 1> values = {CHUNK_SIZE};
                ksnp_stream_qos_params  params = {
                     .chunk_size     = ksnp_qos_u16{.type = ksnp_qos_type::KSNP_QOS_LIST,
                                                    .list = {.values = values.data(), .count = values.size()}},
                     .min_bps        = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0          },
                     .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0          },
                     .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0          },
                     .extensions     = nullptr,
                };
                std::cout << "Invalid QoS\n";
                this->connection().open_stream_fail(
                    ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER, &params, "Unsupported chunk size");
                return true;
            }

            ::ksnp_stream *stream;
            check_error(ksnp_simple_stream_create(&stream, CHUNK_SIZE));

            if (evt.parameters->capacity > 0) {
                std::vector<unsigned char> data(evt.parameters->capacity, 'a');
                check_error(
                    ksnp_simple_stream_add_key_data(stream, ::ksnp_data{.data = data.data(), .len = data.size()}));
            }

            ksnp_stream_accepted_params params = {
                .stream_id      = {},
                .chunk_size     = CHUNK_SIZE,
                .position       = 0,
                .max_key_delay  = 0,
                .min_bps        = ksnp_rate{.bits = 1, .seconds = 0},
                .provision_size = 0,
                .extensions     = nullptr,
            };
            if (uuid_is_null(std::begin(evt.parameters->stream_id))) {
                uuid_generate(std::begin(params.stream_id));
            } else {
                uuid_copy(std::begin(params.stream_id), std::begin(evt.parameters->stream_id));
            }
            std::cout << "Opened stream\n";
            this->connection().open_stream_ok(stream, params);
            return true;
        },
        [](ksnp_server_event_close_stream &evt) -> bool {
            std::cout << "Close stream request\n";
            ksnp_simple_stream_destroy(evt.stream);
            return true;
        },
        [this](ksnp_server_event_suspend_stream &) -> bool {
            this->connection().suspend_stream_fail(ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED,
                                                   "Suspend is not supported by this server");
            return true;
        },
        [this](ksnp_server_event_keep_alive &) -> bool {
            // Suspend not supported
            this->connection().keep_alive_fail(ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED, nullptr);
            return true;
        },
        [this](ksnp_server_event_new_capacity &evt) -> bool {
            std::cout << "New capacity: " << evt.current_capacity << "\n";
            auto                      *stream = this->connection().get_stream();
            std::vector<unsigned char> data(evt.additional_capacity, 'a');
            check_error(ksnp_simple_stream_add_key_data(stream, ::ksnp_data{.data = data.data(), .len = data.size()}));
            return true;
        },
        [](ksnp_server_event_error &evt) -> bool {
            if (evt.stream != nullptr) {
                ksnp_simple_stream_destroy(evt.stream);
            }
            std::cerr << "Protocol error: ";
            if (evt.description != nullptr) {
                std::cerr << evt.description;
            } else if (auto const *desc = ksnp_protocol_error_description(evt.code); desc != nullptr) {
                std::cerr << desc;
            } else {
                std::cerr << static_cast<uint32_t>(evt.code);
            }
            std::cerr << '\n';
            return true;
        },
        [](auto &) -> auto {
            return false;
        },
    };

    if (event.has_value()) {
        return std::visit(visitor, *event);
    }
    return false;
}

namespace
{
auto accept(fd &listen_sock) -> fd
{
    while (true) {
        struct sockaddr peer_addr{};
        socklen_t       peer_addr_size = sizeof(peer_addr);

        fd sock(accept4(*listen_sock, &peer_addr, &peer_addr_size, SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (!sock) {
            switch (errno) {
            case ENETDOWN:
            case EPROTO:
            case ENOPROTOOPT:
            case EHOSTDOWN:
            case ENONET:
            case EHOSTUNREACH:
            case EOPNOTSUPP:
            case ENETUNREACH:
                continue;
            default:
                throw errno_exception(errno, "Failed to accept");
            }
        }
        std::array<char, std::max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)> peer_addr_str{};
        if (auto err = getnameinfo(
                &peer_addr, peer_addr_size, peer_addr_str.data(), peer_addr_str.size(), nullptr, 0, NI_NUMERICHOST);
            err != 0) {
            throw gai_exception(err);
        }
        std::cout << "Connection from " << peer_addr_str.data() << '\n';
        return sock;
    }
}

void run_server(fd sock)
{
    auto srv = server(std::move(sock));

    auto handshake_event = srv.next_event();
    if (!handshake_event.has_value() || !std::holds_alternative<ksnp_server_event_handshake>(*handshake_event)) {
        std::cerr << "First event is not a version\n";
        return;
    }

    std::cout << "Version is "
              << static_cast<uint32_t>(std::get<ksnp_server_event_handshake>(*handshake_event).protocol) << '\n';

    for (auto event = srv.next_event(); event.has_value(); event = srv.next_event()) {
        if (!std::visit(
                [](auto &) -> auto {
                    std::cerr << "Unexpected event\n";
                    return false;
                },
                *event)) {
            return;
        }
    }
}
}  // namespace

auto main(int argc, char *argv[]) noexcept -> int
try {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " addr port" << '\n';
        exit(EXIT_FAILURE);
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        throw errno_exception(errno);
    }

#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    auto listen_sock = listen(argv[1], argv[2]);
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif

    while (true) {
        std::cout << "Waiting for connection\n";
        auto sock = accept(listen_sock);
        run_server(std::move(sock));
    }
} catch (std::exception &e) {
    std::cerr << "Error: " << e.what() << '\n';
    exit(EXIT_FAILURE);
} catch (...) {
    std::terminate();
}
