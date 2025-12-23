#include <cstdint>
#include <optional>
#include <span>

#include "helpers.hpp"
#include "ksnp/client.h"

struct ksnp_client {
private:
    enum class stream_state : uint8_t {
        closed,
        opening,
        open,
        suspending,
        closing,
        error,
    };

    ksnp_message_context                *connection;
    std::optional<ksnp_protocol_version> version;
    stream_state                         stream_state;
    bool                                 in_shutdown;
    uint32_t                             registered_capacity;
    uint16_t                             chunk_size;

public:
    explicit ksnp_client(ksnp_message_context *connection);

    ~ksnp_client() = default;

    ksnp_client(ksnp_client const &) = delete;
    ksnp_client(ksnp_client &&)      = delete;

    auto operator=(ksnp_client const &) -> ksnp_client & = delete;
    auto operator=(ksnp_client &&) -> ksnp_client &      = delete;

    [[nodiscard]] auto want_read() const noexcept -> bool;

    [[nodiscard]] auto read_data(std::span<uint8_t const> data) -> size_t;

    [[nodiscard]] auto want_write() const noexcept -> bool;

    void flush_data();

    [[nodiscard]] auto write_data(std::span<uint8_t> data) -> size_t;

    [[nodiscard]] auto next_event() -> std::optional<ksnp::client_event>;

    void open_stream(ksnp_stream_open_params const *parameters);

    void close_stream();

    void suspend_stream(uint32_t timeout);

    void add_capacity(uint32_t additional_capacity);

    void keep_alive(uuid_t const &stream_id);

    void close_connection(ksnp_close_direction dir);

private:
    /**
     * @brief Handle the given message and act accordingly.
     *
     * @param msg Message that was received that should be acted upon.
     * @return Resulting event, if any.
     */
    [[nodiscard]] auto process_message(ksnp_message const &msg) -> std::optional<ksnp::client_event>;

    /**
     * @brief Add a message to send to the connected server.
     *
     * The message is added to an internal queue.
     *
     * @param msg Message to send to the server.
     */
    void push_message(ksnp::message_t msg);

    /**
     * @brief Register an error and send a protocol error message with the given
     * error code.
     *
     * @param err Error code that matches the error condition.
     * @return A client event to indicate an error occurred.
     */
    auto on_error(ksnp_error_code err) -> ksnp::client_event;
};
