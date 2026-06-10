#include <cstdint>
#include <optional>
#include <span>
#include <variant>

#include "ksnp/client.h"
#include "ksnp/messages.h"
#include "serde.hpp"

namespace ksnp
{

class client_event
    : public std::variant<ksnp_client_event_handshake,
                          ksnp_client_event_stream_open,
                          ksnp_client_event_stream_close,
                          ksnp_client_event_stream_suspend,
                          ksnp_client_event_key_data,
                          ksnp_client_event_keep_alive,
                          ksnp_client_event_error>
{
public:
    using base = std::variant<ksnp_client_event_handshake,
                              ksnp_client_event_stream_open,
                              ksnp_client_event_stream_close,
                              ksnp_client_event_stream_suspend,
                              ksnp_client_event_key_data,
                              ksnp_client_event_keep_alive,
                              ksnp_client_event_error>;
    using base::base;
    using base::operator=;

    static auto from_event(ksnp_client_event event) -> std::optional<client_event>;

    [[nodiscard]] auto into_event() const noexcept -> ksnp_client_event;
};

class client
{
private:
    enum class stream_state : uint8_t {
        closed,
        opening,
        open,
        suspending,
        closing,
        error,
    };

    ksnp::message_context               *connection;
    std::optional<ksnp_protocol_version> version;
    stream_state                         stream_state;
    bool                                 in_shutdown;
    bool                                 give_eof;
    uint32_t                             registered_capacity;
    uint16_t                             chunk_size;

public:
    explicit client(ksnp::message_context &connection);

    ~client() = default;

    client(client const &) = delete;
    client(client &&)      = delete;

    auto operator=(client const &) -> client & = delete;
    auto operator=(client &&) -> client &      = delete;

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
    [[nodiscard]] auto process_message(ksnp::message const &msg) -> std::optional<client_event>;

    /**
     * @brief Add a message to send to the connected server.
     *
     * The message is added to an internal queue.
     *
     * @param msg Message to send to the server.
     */
    void push_message(ksnp::message msg);

    /**
     * @brief Register an error and send a protocol error message with the given
     * error code.
     *
     * @param err Error code that matches the error condition.
     * @return A client event to indicate an error occurred.
     */
    auto on_error(ksnp_error_code err) -> ksnp::client_event;
};

}  // namespace ksnp
