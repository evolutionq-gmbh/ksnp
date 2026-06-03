#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "helpers.hpp"
#include "ksnp/server.h"
#include "ksnp/types.h"
#include "serde.hpp"

struct simple_stream : protected ksnp_stream {
private:
    using diff_type = std::vector<uint8_t>::difference_type;
    using size_type = std::vector<uint8_t>::size_type;

    std::vector<uint8_t> provisioned_data;
    size_type            prev_read;

public:
    explicit simple_stream(uint16_t chunk_size)  // NOLINT(bugprone-easily-swappable-parameters)
        : ksnp_stream
        {
            .chunk_size = chunk_size, .has_chunk_available = &simple_stream::has_chunk_available_fn,
            .next_chunk = &simple_stream::next_chunk_fn,
            .user_data = this,
        }
        , prev_read(0)
    {}

    simple_stream(simple_stream const &) = default;
    simple_stream(simple_stream &&)      = default;

    ~simple_stream() = default;

    auto operator=(simple_stream const &) -> simple_stream & = default;
    auto operator=(simple_stream &&) -> simple_stream &      = default;

    [[nodiscard]] auto has_chunk() const noexcept -> bool
    {
        return (this->provisioned_data.size() - this->prev_read) >= this->chunk_size;
    }

    void add_key_data(std::span<uint8_t const> data)
    {
        if (this->prev_read > 0) {
            this->provisioned_data.erase(this->provisioned_data.begin(),
                                         this->provisioned_data.begin() + static_cast<diff_type>(this->prev_read));
            this->prev_read = 0;
        }
        this->provisioned_data.insert(this->provisioned_data.end(), data.begin(), data.end());
    }

    auto next_chunk(struct ksnp_data *data, uint16_t max_count) noexcept -> ksnp_error
    {
        if (this->prev_read > 0) {
            this->provisioned_data.erase(this->provisioned_data.begin(),
                                         this->provisioned_data.begin() + static_cast<diff_type>(this->prev_read));
        }

        // Always returns exactly 1 chunk.
        (void)max_count;

        auto avail = this->provisioned_data.size();
        if (avail < this->chunk_size) {
            data->data      = nullptr;
            data->len       = 0;
            this->prev_read = 0;
        } else {
            data->data      = const_cast<unsigned char *>(this->provisioned_data.data());
            data->len       = static_cast<size_type>(this->chunk_size);
            this->prev_read = this->chunk_size;
        }

        return ksnp_error::KSNP_E_NO_ERROR;
    }

    static auto from_stream_ptr(ksnp_stream const *base_stream) -> simple_stream const *
    {
        return static_cast<simple_stream const *>(base_stream->user_data);
    }

    static auto from_stream_ptr(ksnp_stream *base_stream) -> simple_stream *
    {
        return static_cast<simple_stream *>(base_stream->user_data);
    }

    auto as_stream_ptr() -> ksnp_stream *
    {
        return this;
    }

private:
    [[nodiscard]] static auto has_chunk_available_fn(ksnp_stream const *base_stream) noexcept -> bool
    {
        return static_cast<simple_stream const *>(base_stream)->has_chunk();
    }

    [[nodiscard]] static auto
    next_chunk_fn(ksnp_stream *base_stream, struct ksnp_data *data, uint16_t max_count) noexcept -> ksnp_error
    {
        return static_cast<simple_stream *>(base_stream)->next_chunk(data, max_count);
    }
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

    ksnp::message_context                         *connection;
    ksnp::unique_obj<ksnp_stream *, ignore_stream> current_stream;
    std::optional<ksnp_protocol_version>           version;

    uint32_t              client_capacity;
    stream_state          stream_state;
    std::optional<action> current_action;
    bool                  in_shutdown;
    bool                  give_eof;

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
    explicit ksnp_server(ksnp::message_context &connection);
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
    [[nodiscard]] auto process_message(ksnp::message const &msg) -> std::optional<ksnp::server_event>;

    /**
     * @brief Add a message to send to the connected client.
     *
     * The message is added to an internal queue. The write_data() method allows
     * the encoded message to be read. Any pointers or references in the message
     * only need to remain valid for the duration of the call.
     *
     * @param msg Message to send to the client.
     */
    void push_message(ksnp::message msg);

    /**
     * @brief Register an error and send a protocol error message with the given
     * error code.
     *
     * @param err Error code that matches the error condition.
     * @return A server event to indicate an error occurred.
     */
    auto on_error(ksnp_error_code err) -> ksnp::server_event;
};
