/**
 * @file client_example.cpp
 * @author evolutionQ GmbH
 * @copyright Copyright (c) 2025
 *
 * @brief This file, together with the common example source, defines a test
 * client that shows how the key stream protocol API can be used.
 *
 * The @ref client class can be used to interact with a server using some open
 * socket, and makes available operations to open a stream, get keys, and close
 * the stream, with semantics similar to those of ETSI 004.
 */

#include <arpa/inet.h>
#include <csignal>
#include <cstdlib>
#include <deque>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <sys/poll.h>
#include <uuid/uuid.h>
#include <variant>

#include "common.hpp"
#include "helpers.hpp"
#include "ksnp/client.h"
#include "ksnp/types.h"

/// @brief Type for key chunks, which are fixed-size byte arrays.
using key_chunk = std::array<unsigned char, CHUNK_SIZE>;

static size_t const MAX_BUFFERED_KEYS = 32;

/**
 * @brief Implementation of a client connection.
 *
 * A client can be used by opening a stream, getting keys from it, and then
 * closing it again.
 *
 * This types handles the details of opening and closing a key stream and
 * buffering key data. It keeps a buffer of 32 chunks available. An attempt to
 * use an index outside of this range will fail.
 */
class client : private connection_handler<client_obj>
{
    std::deque<std::optional<key_chunk>> chunks;
    size_t                               first_chunk;
    bool                                 stream_open;

public:
    explicit client(fd sock) : connection_handler(std::move(sock)), first_chunk(0), stream_open(false)
    {}

    client(client const &) = delete;
    client(client &&)      = delete;

    ~client() override = default;

    auto operator=(client const &) -> client & = delete;
    auto operator=(client &&) -> client &      = delete;

    using connection_handler::next_event;

    /**
     * @brief Open a new key stream using the given key stream parameters.
     *
     * This will perform all necessary operations to establish a key stream.
     *
     * @param parameters Key stream parameters to use for the open request.
     */
    void open(ksnp_stream_open_params parameters)
    {
        if (this->stream_open) {
            std::cerr << "Stream already open\n";
            return;
        }

        parameters.capacity = CHUNK_SIZE * MAX_BUFFERED_KEYS;
        this->connection().open_stream(parameters);
        auto open_event = this->wait_for_event<ksnp_client_event_stream_open>();
        if (!open_event) {
            throw std::runtime_error("Connection closed by server");
        }

        std::array<char, UUID_STR_LEN> uuid_str = {};
        uuid_unparse_lower(std::begin(open_event->parameters.reply->stream_id), uuid_str.data());
        std::cout << "Opened stream " << uuid_str.data() << '\n';
    }

    /**
     * @brief Get a key chunk with the given index from the key stream.
     *
     * Requires that a key stream is open.
     *
     * @param index Index of the key chunk to fetch. Unlike ETSI 004, this is
     * 0-based. Use `nullopt` to fetch the next available key.
     * @return The requested key.
     */
    auto get_key(std::optional<unsigned int> index) -> std::optional<key_chunk>
    {
        if (!this->stream_open) {
            std::cerr << "No open stream\n";
            return {};
        }

        auto get_index = index.value_or(this->first_chunk);

        if (get_index < this->first_chunk || get_index >= this->first_chunk + MAX_BUFFERED_KEYS) {
            std::cerr << "Invalid key index\n";
            return {};
        }

        auto chunk_index = get_index - this->first_chunk;

        while (chunk_index >= this->chunks.size()) {
            if (!this->wait_for_event<ksnp_client_event_key_data>()) {
                throw std::runtime_error("Connection closed by server");
            }
        }

        if (chunk_index >= this->chunks.size() || !this->chunks[chunk_index].has_value()) {
            return {};
        }
        auto chunk = *this->chunks[chunk_index];
        this->chunks[chunk_index].reset();

        uint16_t pop_count = 0;
        while (!this->chunks.empty() && !this->chunks.front().has_value()) {
            this->first_chunk += 1;
            this->chunks.pop_front();
            pop_count += 1;
        }
        if (pop_count > 0) {
            this->connection().add_capacity(CHUNK_SIZE * pop_count);
        }

        return chunk;
    }

    /**
     * @brief Close the current open key stream.
     *
     * Requires that a key stream is open.
     */
    void close_stream()
    {
        if (!this->stream_open) {
            std::cerr << "No open stream\n";
            return;
        }

        this->stream_open = false;
        this->connection().close_stream();
        if (!this->wait_for_event<ksnp_client_event_stream_close>()) {
            throw std::runtime_error("Connection closed by server");
        }
    }

protected:
    auto process_event(client_obj::result_type &event) -> bool override;

private:
    template<typename T>
    auto wait_for_event() -> std::optional<T>
    {
        std::optional<ksnp::client_event> event = std::nullopt;
        while ((event = this->next_event()).has_value()) {
            if (std::holds_alternative<T>(*event)) {
                return std::get<T>(*event);
            }
        }

        return {};
    }
};

auto client::process_event(client_obj::result_type &event) -> bool
{
    auto const visitor = ksnp::overloads{
        [this](ksnp_client_event_stream_open &evt) -> bool {
            if (evt.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
                std::cout << "Server opened the stream\n";
                this->stream_open = true;
            } else {
                std::cout << "Server open stream error " << evt.message << '\n';
                throw ksnp_status_exception(evt.code);
            }
            return false;
        },
        [this](ksnp_client_event_stream_close &) -> bool {
            std::cout << "Server closed the stream\n";
            this->stream_open = false;
            return false;
        },
        [this](ksnp_client_event_stream_suspend &) -> bool {
            // Suspend not supported
            std::cout << "Server suspended the stream\n";
            this->stream_open = false;
            return true;
        },
        [](ksnp_client_event_keep_alive &) -> bool {
            // Suspend not supported
            return true;
        },
        [this](ksnp_client_event_key_data &evt) -> bool {
            std::span<unsigned char const> key_data{evt.key_data.data, evt.key_data.len};
            while (key_data.size() >= CHUNK_SIZE) {
                auto chunk = key_chunk{};
                std::ranges::copy(key_data.subspan(0, CHUNK_SIZE), std::begin(chunk));
                this->chunks.emplace_back(chunk);
                key_data = key_data.subspan(CHUNK_SIZE);
            }
            std::cout << "Received " << (evt.key_data.len / CHUNK_SIZE) << " keys\n";
            if (!key_data.empty()) {
                throw std::runtime_error("Non chunk key data len");
            }
            return false;
        },
        [](ksnp_client_event_handshake &evt) -> bool {
            std::cout << "Handshake complete: Version is " << static_cast<uint32_t>(evt.protocol) << '\n';
            return true;
        },
        [](ksnp_client_event_error &evt) -> bool {
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
    };

    if (event.has_value()) {
        return std::visit(visitor, *event);
    }
    return false;
}

#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <variant>

/**
 * @brief Input parameters for the open stream command.
 */
struct cmd_open_stream {
    std::string                target_sae;
    std::optional<std::string> stream_id;
};

/**
 * @brief Input parameters for the get key command.
 */
struct cmd_get_key {
    std::optional<size_t> key_id;
};

/**
 * @brief Input parameters for the close stream command.
 */
struct cmd_close_stream {};

/**
 * @brief Sentinel for invalid commands.
 */
struct cmd_invalid {};

/// @brief Command alternatives.
using command = std::variant<cmd_open_stream, cmd_get_key, cmd_close_stream, cmd_invalid>;

namespace
{

/**
 * @brief Parse the given line as a command to perform.
 *
 * Note that invalid commands generate cmd_invalid instances.
 *
 * @param line Line to parse.
 * @return The parsed command, or `nullopt` if the line was empty.
 */
auto parse_command(std::string line) -> std::optional<command>
{
    std::istringstream iss(std::move(line));
    std::string        cmd;
    if (!(iss >> cmd)) {
        return std::nullopt;
    }

    std::optional<command> command;

    if (cmd == "open") {
        std::string target;
        if (!(iss >> target)) {
            command = cmd_invalid{};
        } else {
            std::string stream_id;
            if (iss >> stream_id) {
                command = cmd_open_stream{.target_sae = target, .stream_id = stream_id};
            } else {
                command = cmd_open_stream{.target_sae = target, .stream_id = std::nullopt};
            }
        }
    } else if (cmd == "get") {
        size_t key_index;
        if (iss >> key_index) {
            command = cmd_get_key{.key_id = key_index};
        } else {
            command = cmd_get_key{.key_id = std::nullopt};
        }
    } else if (cmd == "close") {
        command = cmd_close_stream{};
    } else {
        command = cmd_invalid{};
    }

    std::string extra;
    if (iss >> extra) {
        return cmd_invalid{};
    }
    return {command};
}
}  // namespace

auto main(int argc, char *argv[]) -> int
try {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " host port" << '\n';
        exit(EXIT_FAILURE);
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        throw errno_exception(errno);
    }

    auto sock = connect(argv[1], argv[2]);

    int flags = check_errno(fcntl(*sock, F_GETFL, 0));
    check_errno(fcntl(*sock, F_SETFL, flags | O_NONBLOCK));

    client clnt(std::move(sock));

    std::string line;
    std::cout << "> " << std::flush;
    while (std::getline(std::cin, line)) {
        auto command = parse_command(line);
        if (!command) {
            continue;
        }

        std::visit(ksnp::overloads{
                       [&clnt](cmd_open_stream const &cmd) -> void {
                           ksnp_stream_open_params params{
                               .stream_id           = {},
                               .source              = {.sae = nullptr, .network = nullptr},
                               .destination         = {.sae = cmd.target_sae.c_str(), .network = nullptr},
                               .chunk_size          = CHUNK_SIZE,
                               .capacity            = 0,
                               .min_bps             = {.bits = 0, .seconds = 0},
                               .max_bps             = {.bits = 0, .seconds = 0},
                               .ttl                 = 0,
                               .provision_size      = 0,
                               .extensions          = nullptr,
                               .required_extensions = nullptr,
                           };
                           if (cmd.stream_id.has_value()) {
                               if (uuid_parse_range(&cmd.stream_id->front(),
                                                    &cmd.stream_id->back() + 1,
                                                    std::begin(params.stream_id))
                                   != 0) {
                                   std::cout << "Invalid stream ID\n";
                                   return;
                               }
                           }
                           clnt.open(params);
                       },
                       [&clnt](cmd_get_key const &cmd) -> void {
                           if (clnt.get_key(cmd.key_id)) {
                               std::cout << "Retrieved key\n";
                           } else {
                               std::cout << "No key\n";
                           }
                       },
                       [&clnt](cmd_close_stream const &) -> void {
                           clnt.close_stream();
                       },
                       [](cmd_invalid) -> void {
                           std::cout << "Invalid command\n";
                       },
                   },
                   *command);
        std::cout << "> " << std::flush;
    }

    exit(EXIT_SUCCESS);
} catch (std::exception const &e) {
    std::cerr << "Error: " << e.what() << '\n';
    exit(EXIT_FAILURE);
} catch (...) {
    std::terminate();
}
