#include <cstdint>
#include <optional>
#include <span>
#include <variant>

#include "ksnp/client.h"
#include "serde.hpp"

namespace ksnp
{

/**
 * @brief Any event that may be triggered by the client processing server data.
 */
class client_event
    : public std::variant<ksnp_client_event_handshake,
                          ksnp_client_event_stream_open,
                          ksnp_client_event_stream_close,
                          ksnp_client_event_stream_suspend,
                          ksnp_client_event_key_data,
                          ksnp_client_event_keep_alive,
                          ksnp_client_event_error>
{
private:
    using base = std::variant<ksnp_client_event_handshake,
                              ksnp_client_event_stream_open,
                              ksnp_client_event_stream_close,
                              ksnp_client_event_stream_suspend,
                              ksnp_client_event_key_data,
                              ksnp_client_event_keep_alive,
                              ksnp_client_event_error>;

public:
    using base::base;
    using base::operator=;

    /**
     * @brief Convert a C API event into this event type.
     */
    static auto from_event(ksnp_client_event event) -> std::optional<client_event>;

    /**
     * @brief Convert this event into a C API event.
     *
     * @return A C API event. The lifetime of the event may not exceed that of
     * this object.
     */
    [[nodiscard]] auto into_event() const noexcept -> ksnp_client_event;
};

/**
 * @class client
 * @brief A type for managing the protocol state machine and messages for client
 * connections.
 *
 * This type can be used to read and write message data for a client, and ensure
 * the protocol is followed correctly.
 *
 * To use a client, data must be read and written using @ref read_data() and
 * @ref write_data(), which respectively read received server data and write
 * data to send to the server. If a message context is used with external
 * buffers, data may be directly read from and written to those.
 *
 * After receiving data from the server, @ref next_event() should be called as
 * soon as possible to process the message data and handle the corresponding
 * events.
 *
 * To check if the client requires more data from the server, or has data to
 * send to the server, the @ref want_read() and @ref want_write() functions can
 * be used. If either of these returns true, data should be read from or written
 * to the client as appropriate.
 *
 * This type cannot be used concurrently across threads, but can be shared
 * between threads.
 */
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
    /**
     * @brief Construct a new client object with a given message context.
     *
     * @param connection The message context representing the connection to the
     * server. This object must outlive the client instance.
     */
    explicit client(ksnp::message_context &connection);

    ~client() = default;

    client(client const &) = delete;
    /** @brief Move the client instance. */
    client(client &&)      = default;

    auto operator=(client const &) -> client & = delete;
    /** @brief Move the given client instance into this instance. */
    auto operator=(client &&) -> client &      = default;

    /**
     * @brief Check if the client is ready to receive more data.
     *
     * This function can be used to determine whether more data is expected from
     * the server. If so, the client does not have any data available to
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
     * @brief Provide more data for the client to read.
     *
     * This function can be used to provide the client with further data
     * received from the server. The client buffers this data until it is ready
     * to be processed. To prevent this buffer from growing unduly (or filling
     * up entirely), the @ref want_read() function should be used to determine
     * when it is appropriate to add more data.
     *
     * After calling this function, @ref next_event() should be called as soon
     * as possible, or when @ref want_read() returns false.
     *
     * To indicate the receiving channel from the server has been closed, i.e.,
     * EOF was reached, use @ref close_connection().
     *
     * @param data Buffer containing more data.
     * @return The number of bytes actually read, which may be less than the
     * input if the buffer of the associated message context does not have
     * sufficient capacity.
     */
    [[nodiscard]] auto read_data(std::span<uint8_t const> data) -> size_t;

    /**
     * @brief Check if the client has data available to write.
     *
     * This function can be used to determine whether the client has any data
     * available to send to the server, which can be retrieved using @ref
     * write_data() or be made available using @ref flush_data().
     *
     * This function also returns true if previously the connection was closed
     * in the write direction, and no data needs to be sent to the client. In
     * that case @ref write_data() or @ref flush_data() will result in empty
     * buffers, and the outgoing connection should be closed.
     *
     * @return true if data is available for writing, and @ref write_data() or
     * @ref flush_data() should be called as soon as the connection with the
     * server is willing to accept it, or when the outgoing connection is
     * closing, in which case @ref write_data() or @ref flush_data() yield no
     * data to write.
     * @return false if no data is available to be written.
     */
    [[nodiscard]] auto want_write() const noexcept -> bool;

    /**
     * @brief Flush pending data to the write buffer.
     *
     * This function can be used to flush data that should be written to the
     * server to the write buffer, without having to call @ref write_data().
     * This is necessary when using a message context with custom buffers.
     *
     * If @ref want_write() has returned true, but no data is in the buffer
     * after calling this function, the outgoing connection should be closed.
     */
    void flush_data();

    /**
     * @brief Retrieve data from the client to send to the server.
     *
     * This function can be used to retrieve the data from the client that needs to
     * be sent to the server. This is normally called when calling
     * @ref want_write() returns true. The client buffers this data until it is
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
    [[nodiscard]] auto next_event() -> std::optional<ksnp::client_event>;

    /**
     * @brief Request to open a new key stream.
     *
     * This function can be used to request a new key stream or reopen a
     * suspended stream on a connection without an associated key stream.
     *
     * The request is not complete until a @ref ksnp_client_event_stream_open
     * occurs, which contains the result of the request.
     *
     * @param parameters Pointer to the parameters for the key stream.
     */
    void open_stream(ksnp_stream_open_params const *parameters);

    /**
     * @brief Request to close the open stream.
     *
     * This function can be used to close the key stream currently open.
     *
     * The request is not complete until a @ref ksnp_client_event_stream_close
     * occurs.
     */
    void close_stream();

    /**
     * @brief Request to suspend the open stream.
     *
     * This function can be used to request to suspend the key stream currently
     * open. The @p timeout parameter is used to indicate the desired minimum
     * time to keep the stream suspended for.
     *
     * The request is not complete until a @ref ksnp_client_event_stream_suspend
     * occurs, which contains the result of the request.
     *
     * @param timeout Time in seconds to keep the stream suspended for. Note
     * that the server may choose a different timeout, which is returned in the
     * @ref ksnp_client_event_stream_suspend event.
     */
    void suspend_stream(uint32_t timeout);

    /**
     * @brief Indicate further capacity for key data is available.
     *
     * This function can be used to indicate to the server further key data
     * capacity is available for the stream currently open.
     *
     * Note that the total available capacity may not exceed UINT32_MAX.
     *
     * @param additional_capacity Additional capacity in bytes that is available
     * for receiving key data.
     */
    void add_capacity(uint32_t additional_capacity);

    /**
     * @brief Send a keep alive notification for a suspended stream.
     *
     * This function can be used to send a keep alive message to the server for a
     * suspended stream.
     *
     * The stream identified by @p stream_id must have been previously suspended.
     *
     * The request is not complete until a ksnp_client_event_keep_alive occurs,
     * which contains the result of the request.
     *
     * @param stream_id The identifier of the key stream to keep alive.
     */
    void keep_alive(uuid_t const &stream_id);

    /**
     * @brief Close the connection with the server in a particular direction.
     *
     * The read direction must be closed as soon as the server indicates it has
     * closed the connection. If the read direction is closed, no further
     * message data will be accepted. The write direction should be closed when
     * either the server has closed the connection and next_event() returns no
     * event, or when the client itself is stopping.
     *
     * If the write direction is closed, any ongoing event is cancelled. The
     * client will accept incoming data until the read direction is closed, but
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
