#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <json-c/json.h>

#include "helpers.hpp"
#include "ksnp/server.h"
#include "ksnp/types.h"

struct simple_stream : ksnp_stream {
private:
    using diff_t = std::vector<uint8_t>::difference_type;

    std::vector<uint8_t> provisioned_data;
    size_t               prev_read;

public:
    explicit simple_stream(uint16_t chunk_size)  // NOLINT(bugprone-easily-swappable-parameters)
        : ksnp_stream
        {
            .chunk_size=chunk_size,
            .has_chunk_available = &simple_stream::stream_has_chunk,
            .next_chunk = &simple_stream::stream_next_chunk,
        }
        , prev_read(0)
    {}

    void add_key_data(std::span<uint8_t const> data);

private:
    /**
     * @brief Retrieve the next available chunk of key data, if any.
     *
     * The resulting span is valid only until the next call to @ref next_chunk or @ref add_key_data.
     *
     * @return A span containing the key data to sent (which is a multiple of
     * the chunk size), or nothing if no key data is available.
     */
    auto next_chunk() -> std::optional<std::span<uint8_t const>>;

    [[nodiscard]] static auto stream_has_chunk(ksnp_stream const *stream) noexcept -> bool;
    [[nodiscard]] static auto
    stream_next_chunk(ksnp_stream *stream, struct ksnp_data *data, uint16_t max_count) noexcept -> ksnp_error;
};

struct ksnp_server {
private:
    enum class stream_state : uint8_t {
        closed,
        open,
        suspending,
        closing,
        error,
    };

    enum class action : uint8_t {
        opening,
        suspending,
        keep_alive,
    };

    static void ignore_stream(ksnp_stream *stream)
    {
        (void)stream;
    }

    ksnp_message_context                          *connection;
    ksnp::unique_obj<ksnp_stream *, ignore_stream> current_stream;
    std::optional<ksnp_protocol_version>           version;

    uint32_t              client_capacity;
    stream_state          stream_state;
    std::optional<action> current_action;
    bool                  in_shutdown;

public:
    /**
     * @brief Construct a new server connection object using the given
     * connection to a client.
     *
     * The connection is only used by reference. It must remain valid for the
     * duration if this object's lifetime.
     *
     * @param connection Client connection.
     */
    explicit ksnp_server(ksnp_message_context *connection);
    ~ksnp_server() = default;

    ksnp_server(ksnp_server const &) = delete;
    ksnp_server(ksnp_server &&)      = delete;

    auto operator=(ksnp_server const &) -> ksnp_server & = delete;
    auto operator=(ksnp_server &&) -> ksnp_server &      = delete;

    [[nodiscard]] auto get_stream() const noexcept -> ksnp_stream *
    {
        return this->current_stream.get();
    }

    [[nodiscard]] auto want_read() const noexcept -> bool;

    [[nodiscard]] auto read_data(std::span<uint8_t const> data) -> size_t;

    [[nodiscard]] auto next_event() -> std::optional<ksnp::server_event>;

    [[nodiscard]] auto want_write() const noexcept -> bool;

    void flush_data();

    [[nodiscard]] auto write_data(std::span<uint8_t> data) -> size_t;

    void open_stream_ok(::ksnp_stream *stream, struct ksnp_stream_accepted_params const *params);
    void open_stream_fail(ksnp_status_code reason, struct ksnp_stream_qos_params const *params, char const *message);

    [[nodiscard]] auto close_stream() -> ksnp_stream *;
    [[nodiscard]] auto suspend_stream_ok(uint32_t timeout) -> ksnp_stream *;
    void               suspend_stream_fail(ksnp_status_code reason, char const *message);

    void keep_alive_ok();
    void keep_alive_fail(ksnp_status_code reason, char const *message);

    void close_connection(ksnp_close_direction dir);

private:
    [[nodiscard]] auto process_message(ksnp_message const &msg) -> std::optional<ksnp::server_event>;

    /**
     * @brief Add a message to send to the connected client.
     *
     * The message is added to an internal queue. The write_data() method allows
     * the encoded message to be read. Any pointers or references in the message
     * only need to remain valid for the duration of the call.
     *
     * @param msg Message to send to the client.
     */
    void push_message(ksnp::message_t msg);

    /**
     * @brief Register an error and send a protocol error message with the given
     * error code.
     *
     * @param err Error code that matches the error condition.
     * @return A server event to indicate an error occurred.
     */
    auto on_error(ksnp_error_code err) -> ksnp::server_event;
};
