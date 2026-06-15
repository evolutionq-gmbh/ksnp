#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "ksnp/server.h"
#include "ksnp/types.h"
#include "ksnp/types.hpp"
#include "serde.hpp"

namespace ksnp
{

/**
 * @brief A stream that does nothing more than buffer inserted key data until it
 * is extracted by the server.
 */
struct simple_stream : protected ksnp_stream {
private:
    using diff_type = std::vector<uint8_t>::difference_type;
    using size_type = std::vector<uint8_t>::size_type;

    std::vector<uint8_t> provisioned_data;
    size_type            prev_read;

public:
    /**
     * @brief Construct a new simple stream.
     *
     * @param chunk_size Size of chunks for the key stream.
     */
    explicit simple_stream(uint16_t chunk_size)  // NOLINT(bugprone-easily-swappable-parameters)
        : ksnp_stream
        {
            .chunk_size = chunk_size, .has_chunk_available = &simple_stream::has_chunk_available_fn,
            .next_chunk = &simple_stream::next_chunk_fn,
            .user_data = this,
        }
        , prev_read(0)
    {}

    /** @brief Copy the given stream into this instance. */
    simple_stream(simple_stream const &) = default;
    /** @brief Move the given stream into this instance. */
    simple_stream(simple_stream &&)      = default;

    ~simple_stream() = default;

    /** @brief Copy the given stream into this instance. */
    auto operator=(simple_stream const &) -> simple_stream & = default;
    /** @brief Move the given stream into this instance. */
    auto operator=(simple_stream &&) -> simple_stream &      = default;

    /**
     * @brief Insert additional key data into the stream.
     *
     * This is normally called as soon as key data becomes available, or the
     * client has indicated it has sufficient capacity for more key data chunks.
     *
     * @param key_data Key data to insert.
     */
    void add_key_data(std::span<uint8_t const> key_data)
    {
        if (this->prev_read > 0) {
            this->provisioned_data.erase(this->provisioned_data.begin(),
                                         this->provisioned_data.begin() + static_cast<diff_type>(this->prev_read));
            this->prev_read = 0;
        }
        this->provisioned_data.insert(this->provisioned_data.end(), key_data.begin(), key_data.end());
    }

    /**
     * @brief Check if a complete chunk of key data is available.
     *
     * @return true if at least a chunk of data is available.
     * @return false otherwise.
     */
    [[nodiscard]] auto has_chunk() const noexcept -> bool
    {
        return (this->provisioned_data.size() - this->prev_read) >= this->chunk_size;
    }

    /**
     * @brief Extracts the next available chunk.
     *
     * @param data [out] Pointer to the structure that describes the chunk data.
     * @param max_count Number of chunks to extract. Ignored, always at most one
     * chunk is extracted.
     * @return NO_ERROR.
     */
    auto next_chunk(struct ksnp_cdata *data, uint16_t max_count) noexcept -> ksnp_error
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

    /**
     * @brief Get a simple_stream pointer from a C API ksnp_stream pointer.
     *
     * @param base_stream C API stream pointer. Must have been created using
     * @ref as_stream_ptr().
     * @return Pointer to a simple_stream.
     */
    static auto from_stream_ptr(ksnp_stream const *base_stream) -> simple_stream const *
    {
        return static_cast<simple_stream const *>(base_stream->user_data);
    }

    /**
     * @brief Get a simple_stream pointer from a C API ksnp_stream pointer.
     *
     * @param base_stream C API stream pointer. Must have been created using
     * @ref as_stream_ptr().
     * @return Pointer to a simple_stream.
     */
    static auto from_stream_ptr(ksnp_stream *base_stream) -> simple_stream *
    {
        return static_cast<simple_stream *>(base_stream->user_data);
    }

    /**
     * @brief Return a C API ksnp_stream pointer that can be used with the C
     * API.
     *
     * @return A ksnp_stream pointer that allows this instance to be used with
     * the C API. The lifetime of the pointer may not exceed that of this
     * object.
     */
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
    next_chunk_fn(ksnp_stream *base_stream, struct ksnp_cdata *data, uint16_t max_count) noexcept -> ksnp_error
    {
        return static_cast<simple_stream *>(base_stream)->next_chunk(data, max_count);
    }
};

/**
 * @brief Any event that may be triggered by the server processing client data.
 */
class server_event
    : public std::variant<ksnp_server_event_handshake,
                          ksnp_server_event_open_stream,
                          ksnp_server_event_close_stream,
                          ksnp_server_event_suspend_stream,
                          ksnp_server_event_keep_alive,
                          ksnp_server_event_new_capacity,
                          ksnp_server_event_error>
{
private:
    using base = std::variant<ksnp_server_event_handshake,
                              ksnp_server_event_open_stream,
                              ksnp_server_event_close_stream,
                              ksnp_server_event_suspend_stream,
                              ksnp_server_event_keep_alive,
                              ksnp_server_event_new_capacity,
                              ksnp_server_event_error>;

public:
    using base::base;
    using base::operator=;

    /**
     * @brief Convert a C API event into this event type.
     */
    static auto from_event(ksnp_server_event event) -> std::optional<server_event>;

    /**
     * @brief Convert this event into a C API event.
     *
     * @return A C API event. The lifetime of the event may not exceed that of
     * this object.
     */
    [[nodiscard]] auto into_event() const noexcept -> ksnp_server_event;
};

/**
 * @struct server
 * @brief A type for managing the protocol state machine and messages for server
 * connections.
 *
 * This type can be used to read and write message data for a server, and ensure
 * the protocol is followed correctly.
 *
 * To use a server, data must be read and written using @ref read_data() and
 * @ref write_data(), which respectively read received client data and write
 * data to send to the client. If a message context is used with external
 * buffers, data may be directly read from and written to those.
 *
 * After receiving data from the client, @ref next_event() should be
 * called as soon as possible to process the message data and handle the
 * corresponding events.
 *
 * To check if the server requires more data from the client, or has data to
 * send to the client, the @ref want_read() and @ref want_write() functions can
 * be used. If either of these returns true, the @ref read_data() and @ref
 * write_data() functions should be called as appropriate.
 *
 * This type cannot be used concurrently across threads, but can be shared
 * between threads.
 */
class server
{
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
     * @brief Construct a new server object with a given message context.
     *
     * @param connection The message context representing the connection to the
     * client. This object must outlive the server instance.
     */
    explicit server(ksnp::message_context &connection);

    ~server() = default;

    server(server const &) = delete;
    /** @brief Move the server instance. */
    server(server &&)      = default;

    auto operator=(server const &) -> server & = delete;
    /** @brief Move the given server instance into this instance. */
    auto operator=(server &&) -> server &      = default;

    /**
     * @brief Check if the server is ready to receive more data.
     *
     * This function can be used to determine whether more data is expected from
     * the client. If so, the server does not have any data available to
     * process, and more input data is to be provided via @ref read_data(). This
     * will always returns false once EOF has been indicated using @ref
     * close_connection().
     *
     * @return true if no complete message is available for processing, and
     * @ref read_data() should be called as soon as more data is available.
     * @return false if some message data is available and @ref next_event()
     * should be called as soon as possible.
     */
    [[nodiscard]] auto want_read() const noexcept -> bool;

    /**
     * @brief Provide more data for the server to read.
     *
     * This function can be used to provide the server with further data
     * received from the client. The server buffers this data until it is ready
     * to be processed. To prevent this buffer from growing unduly (or filling
     * up entirely), the @ref want_read() function should be used to determine
     * when it is appropriate to add more data.
     *
     * After calling this function, @ref next_event() should be called as soon
     * as possible, or when @ref want_read() returns false.
     *
     * To indicate the receiving channel from the client has been closed, i.e.,
     * EOF was reached, use @ref close_connection().
     *
     * @param data Buffer containing more data.
     * @return The number of bytes actually read, which may be less than the
     * input if the buffer of the associated message context does not have
     * sufficient capacity.
     */
    [[nodiscard]] auto read_data(std::span<uint8_t const> data) -> size_t;

    /**
     * @brief Check if the server has data available to write.
     *
     * This function can be used to determine whether the server has any data
     * available to send to the client, which can be retrieved using @ref
     * write_data() or be made available using @ref flush_data().
     *
     * This function also returns true if previously the connection was closed
     * in the write direction, and no data needs to be sent to the client. In
     * that case @ref write_data() or @ref flush_data() will result in empty
     * buffers, and the outgoing connection should be closed.
     *
     * @return true if data is available for writing, and @ref write_data() or
     * @ref flush_data() should be called as soon as the connection with the
     * client is willing to accept it, or when the outgoing connection is
     * closing, in which case @ref write_data() or @ref flush_data() yield no
     * data to write.
     * @return false if no data is available to be written.
     */
    [[nodiscard]] auto want_write() const noexcept -> bool;

    /**
     * @brief Flush pending data to the write buffer.
     *
     * This function can be used to flush data that should be written to the
     * client to the write buffer, without having to call @ref write_data().
     * This is necessary when using a message context with custom buffers.
     *
     * If @ref want_write() has returned true, but no data is in the buffer
     * after calling this function, the outgoing connection should be closed.
     */
    void flush_data();

    /**
     * @brief Retrieve data from the server to send to the client.
     *
     * This function can be used to retrieve the data from the server that needs to
     * be sent to the client. This is normally called when calling
     * @ref want_write() returns true. The server buffers this data until it is
     * retrieved. To prevent this buffer from growing unduly (or filling up
     * entirely), the @ref want_write() function should be used to determine
     * when it is appropriate to retrieve further data.
     *
     * @param data [out] Buffer to write data to.
     * @return The number of bytes actually written, which may be 0. A length of
     * 0 indicates the outgoing connection can be closed if @ref want_write()
     * has returned true immediately beforehand.
     */
    [[nodiscard]] auto write_data(std::span<uint8_t> data) -> size_t;

    /**
     * @brief Process received data.
     *
     * This function will process the received data, reading all incoming
     * messages until either no further messages can be processed, or an event
     * has occurred that needs to be responded to.
     *
     * Most often, this function can be called right after @ref read_data() was
     * called, or immediately after handling an event returned by a previous
     * call to this function.
     *
     * Processing data may optionally result in an event. If it does, the caller
     * should handle the event as appropriate, and call this function again.
     * Otherwise, no further events will become available until further data has
     * been read or written.
     *
     * The data in the resulting event is valid only until the next call to this
     * function, @ref read_data(), this object is destroyed or when the
     * underlying buffer of the message context is modified.
     *
     * Calling this function may result in output data being generated, which
     * can be tested for using @ref want_write().
     *
     * @return An optional client event.
     */
    [[nodiscard]] auto next_event() -> std::optional<server_event>;

    /**
     * @brief Retrieve a pointer to the currently associated stream, if any.
     *
     * This function can be used to retrieve a pointer to the associated stream.
     * The pointer may be used until the next function that uses the server is
     * called. Any of the members defined for the @ref ksnp_stream struct may
     * not be modified.
     *
     * @return Pointer to the associated stream.
     * @return NULL if no stream is associated.
     */
    [[nodiscard]] auto get_stream() const noexcept -> ksnp_stream *
    {
        return this->current_stream.get();
    }

    /**
     * @brief Open a stream.
     *
     * This function may be called to open a stream in response to a
     * @ref ksnp_server_event_open_stream event. It is used when a stream could
     * successfully be opened.
     *
     * @param stream Stream to associate with the server. The server will not
     * own the stream, however it keeps a reference to it until the stream is
     * closed or suspended. Its public members should not be modified as long as
     * the server holds a reference to it.
     * @param params Stream parameters to send to the client.
     */
    void open_stream_ok(::ksnp_stream *stream, struct ksnp_stream_accepted_params const *params);

    /**
     * @brief Indicate failure to open a stream.
     *
     * This function may be called to indicate failure to open a stream in
     * response to a @ref ksnp_server_event_open_stream event.
     *
     * @param reason Code indicating the reason the stream could not be opened.
     * @param params [optional] QoS parameters to send if the stream could not be
     * opened due to the QoS constraints specified in the request.
     * @param message [optional] Message to send to the client to indicate the
     * reason the stream could not be opened.
     */
    void open_stream_fail(ksnp_status_code reason, struct ksnp_stream_qos_params const *params, char const *message);

    /**
     * @brief Close the associated stream.
     *
     * This function can be called in response to the @ref
     * ksnp_server_event_close_stream event, or some other external event.
     *
     * @return The pointer to the associated stream.
     */
    [[nodiscard]] auto close_stream() -> ksnp_stream *;

    /**
     * @brief Suspend the associated stream.
     *
     * This function can be called in response to the
     * @ref ksnp_server_event_suspend_stream event, or some other external event.
     *
     * @param timeout Time in seconds the stream will remain suspended for, as
     * long as the client does not attempt to interact with it.
     * @return The pointer to the associated stream.
     */
    [[nodiscard]] auto suspend_stream_ok(uint32_t timeout) -> ksnp_stream *;

    /**
     * @brief Indicate failure to suspend a stream.
     *
     * This function may be called to indicate failure to suspend a stream in
     * response to a @ref ksnp_server_event_suspend_stream event.
     *
     * @param reason Code indicating the reason the stream could not be
     * suspended.
     * @param message [optional] Message to send to the client to indicate the
     * reason the stream could not be suspended.
     */
    void suspend_stream_fail(ksnp_status_code reason, char const *message);

    /**
     * @brief Indicate a keep alive request was successfully handled.
     *
     * This function may be called to indicate a keep alive in response to a
     * @ref ksnp_server_event_keep_alive event was successful.
     */
    void keep_alive_ok();

    /**
     * @brief Indicate failure to keep alive a suspended stream.
     *
     * This function may be called to indicate failure to keep alive a stream in
     * response to a @ref ksnp_server_event_keep_alive event.
     *
     * @param reason Code indicating the reason the keep alive could not be
     * applied.
     * @param message [optional] Message to send to the client to indicate the
     * reason the stream could not be kept alive.
     */
    void keep_alive_fail(ksnp_status_code reason, char const *message);

    /**
     * @brief Close the connection with the client in a particular direction.
     *
     * The read direction must be closed as soon as the client indicates it has
     * closed the connection. If the read direction is closed, no further
     * message data will be accepted. The write direction should be closed when
     * either the client has closed the connection and next_event() returns no
     * event, or when the server itself is stopping.
     *
     * If the write direction is closed, any ongoing event is cancelled. The
     * server will accept incoming data until the read direction is closed, but
     * will not generate any data to write. After calling this function, the
     * outgoing connection must be closed as soon as @ref want_write() returns
     * true and the write buffer is empty after flushing.
     *
     * @param dir The direction to close.
     */
    void close_connection(ksnp_close_direction dir);

private:
    /**
     * @brief Handle the given message and act accordingly.
     *
     * @param msg Message that was received that should be acted upon.
     * @return Resulting event, if any.
     */
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

}  // namespace ksnp
