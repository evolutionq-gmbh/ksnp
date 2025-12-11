/**
 * @file server.h
 * @copyright Copyright 2025 evolutionQ GmbH. Licensed under the BSD-3-Clause
 * license, see LICENSE.
 *
 * @brief Handling the server state machine for key stream connections.
 *
 * This header defines the types and functions for handling the server state
 * machine for a single server connection, primarily @ref ksnp_server.
 */

#pragma once

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#include <uuid/uuid.h>

#include "ksnp/types.h"

#include "ksnp/compat.h"

// NOLINTBEGIN(modernize-use-trailing-return-type)

struct ksnp_message_context;

/**
 * @brief Enumeration of possible event types that can be set in the
 * @ref ksnp_server_event struct.
 */
ENUM_TYPE(ksnp_server_event_type, uint8_t){
    /// @brief No event has occurred.
    KSNP_SERVER_EVENT_NONE,
    /// @brief The @a handshake event.
    KSNP_SERVER_EVENT_HANDSHAKE,
    /// @brief The @a open_stream event.
    KSNP_SERVER_EVENT_OPEN_STREAM,
    /// @brief The @a close_stream event.
    KSNP_SERVER_EVENT_CLOSE_STREAM,
    /// @brief The @a suspend_stream event.
    KSNP_SERVER_EVENT_SUSPEND_STREAM,
    /// @brief The @a new_capacity event.
    KSNP_SERVER_EVENT_NEW_CAPACITY,
    /// @brief The @a keep_alive event.
    KSNP_SERVER_EVENT_KEEP_ALIVE,
    /// @brief The @a error event.
    KSNP_SERVER_EVENT_ERROR,
};

/// @brief Concrete type for @ref ksnp_server_event_type.
ENUM_TYPE_T(ksnp_server_event_type, uint8_t);

/**
 * @brief Event indicating the initial handshake has completed.
 *
 * This event is sent if the handshake has completed and the protocol version
 * has been established.
 */
struct ksnp_server_event_handshake {
    /// @brief The agreed upon protocol version.
    ksnp_protocol_version protocol;
};

/**
 * @brief Event indicating a new stream must be opened.
 *
 * This event should lead to the server opening a stream.
 *
 * @sa @ref ksnp_server_open_stream_ok()
 * @sa @ref ksnp_server_open_stream_fail()
 */
struct ksnp_server_event_open_stream {
    /// @brief Parameters sent by the client for the stream.
    struct ksnp_stream_open_params const *parameters;
};

/**
 * @brief Event indicating the current stream has been closed by the client.
 *
 * The stream contained by the server connection is returned via this event.
 * Further close operations should not be attempted.
 */
struct ksnp_server_event_close_stream {
    /// @brief The stream previously held by the server connection.
    struct ksnp_stream *stream;
};

/**
 * @brief Event indicating the client wants to suspend the stream.
 *
 * This event should lead to the server suspending, or closing, the stream.
 *
 * @sa @ref ksnp_server_suspend_stream_ok()
 * @sa @ref ksnp_server_suspend_stream_fail()
 * @sa @ref ksnp_server_close_stream()
 */
struct ksnp_server_event_suspend_stream {
    /// The timeout requested by the client.
    uint32_t timeout;
};

/**
 * @brief Event indicating the client has sent a keep alive request.
 *
 * @sa @ref ksnp_server_keep_alive_ok()
 * @sa @ref ksnp_server_keep_alive_fail()
 */
struct ksnp_server_event_keep_alive {
    /// @brief ID of the stream to keep alive.
    uuid_t stream_id;
};

/**
 * @brief Event indicating the client has send additional capacity.
 *
 * The server implementation may use this event to begin allocating key data to
 * the associated stream.
 */
struct ksnp_server_event_new_capacity {
    /// @brief Capacity added by the client.
    uint32_t additional_capacity;
    /// @brief Capacity currently available at the client.
    uint32_t current_capacity;
};

/**
 * @brief Event indicating a protocol error has occurred.
 *
 * This event occurs as a result of either the server detecting a protocol
 * violation or the client sending a protocol violation error. The @a code
 * member contains the reason for the error.
 *
 * If this event is received, the server should not attempt to read further
 * data, send all remaining pending data and close the connection.
 */
struct ksnp_server_event_error {
    /// @brief Reason for the error.
    ksnp_error_code     code;
    /// @brief Optional human readable description of the reason of the error.
    /// This pointer, if not NULL, is valid until the next operation is
    /// performed on the server from which this event originates.
    char const         *description;
    /// @brief Pointer to the previously open stream, if any.
    struct ksnp_stream *stream;
};

/**
 * @brief Any event that may be triggered by the server processing client data.
 */
struct ksnp_server_event {
    /// @brief Type of the contained event, which determines which field of the
    /// union is set, and must be a value from the @ref ksnp_server_event_type
    /// enumeration.
    ksnp_server_event_type type;
    union {
        int                                     none;
        struct ksnp_server_event_handshake      handshake;
        struct ksnp_server_event_open_stream    open_stream;
        struct ksnp_server_event_close_stream   close_stream;
        struct ksnp_server_event_suspend_stream suspend_stream;
        struct ksnp_server_event_new_capacity   new_capacity;
        struct ksnp_server_event_keep_alive     keep_alive;
        struct ksnp_server_event_error          error;
    };
};

/**
 * @brief An abstract key stream.
 *
 * A stream can keep track of buffered key data and be assigned to a single
 * active server connection.
 *
 * Concrete implementations should provide a means of inserting key data and
 * matching the parameters of an open stream request.
 */
struct ksnp_stream {
    /// @brief The chunk size for key data chunks.
    ///
    /// This is the size of chunks that @a has_chunk_available and @a next_chunk
    /// must take into account.
    uint16_t chunk_size;

    /// @brief Pointer to a function that checks if enough key data is available
    /// such that @a next_chunk will return at least one chunk.
    ///
    /// @return true if at least one chunk is available.
    /// @return false if the available key data is not sufficient for a single
    /// chunk.
    bool (*has_chunk_available)(struct ksnp_stream const *stream) NOEXCEPT;

    /// @brief Pointer to a function that extracts key data from the stream in
    /// multiples of the chunk size.
    ///
    /// @param chunk_data Points to a buffer to receive key data, which must
    /// remain valid as long as the stream is not modified, at the longest until
    /// the next call to this function. The size of the buffer must be an exact
    /// multiple of the chunk size.
    /// @param max_count Indicates how many chunks are to be received at most.
    /// If 0, all key data buffered so far may be returned.
    /// @return @ref KSNP_E_NO_ERROR If the method completed successfully. It
    /// may still not result in chunk data if insufficient data is available.
    /// @return Any of the values from the @ref ksnp_error enum on failure.
    ksnp_error (*next_chunk)(struct ksnp_stream *stream, struct ksnp_data *chunk_data, uint16_t max_count) NOEXCEPT;
};

/**
 * @brief Creates a simple stream, which is a stream that does nothing more
 * than buffer inserted key data until it is extracted by the server.
 *
 * The resulting stream must be destroyed using ksnp_simple_stream_destroy() to
 * free all associated resources.
 *
 * @param stream_ptr Pointer where the pointer to the resulting stream is
 * stored.
 * @param chunk_size Size of chunks for the key stream.
 * @return NO_ERROR If the method completed successfully.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_simple_stream_create(struct ksnp_stream **stream_ptr, uint16_t chunk_size) NOEXCEPT;

/**
 * @brief Destroys a previously created simple stream.
 *
 * @param stream Stream to destroy.
 */
void ksnp_simple_stream_destroy(struct ksnp_stream *stream) NOEXCEPT;

/**
 * @brief Insert additional key data into the stream.
 *
 * This is normally called as soon as key data becomes available, or the client
 * has indicated it has sufficient capacity for more key data chunks.
 *
 * @param stream Stream to add key data to.
 * @param key_data Key data to insert.
 * @return NO_ERROR If the method completed successfully.
 * @return Any of the values from the @ref ksnp_error enum on failure. No key data
 * is inserted on error.
 */
NODISCARD ksnp_error ksnp_simple_stream_add_key_data(struct ksnp_stream *stream, struct ksnp_data key_data) NOEXCEPT;

/**
 * @struct ksnp_server
 * @brief A type for managing the protocol state machine and messages for server
 * connections.
 *
 * This type can be used to read and write message data for a server, and ensure
 * the protocol is followed correctly.
 *
 * A server can be created using @ref ksnp_server_create(). To use it, data must
 * be read and written using @ref ksnp_server_read_data() and @ref
 * ksnp_server_write_data(), which respectively read received client data and
 * write data to send to the client.
 *
 * After receiving data from the client, @ref ksnp_server_next_event() should be
 * called as soon as possible to process the message data and handle the
 * corresponding events.
 *
 * To check if the server requires more data from the client, or has data to
 * send to the client, the @ref ksnp_server_want_read() and @ref ksnp_server_want_write()
 * functions can be used. If either of these returns true, the
 * @ref ksnp_server_read_data() and @ref ksnp_server_write_data() functions
 * should be called as appropriate.
 *
 * This type cannot be used concurrently across threads, but can be shared
 * between threads.
 */
struct ksnp_server;

/**
 * @brief Create a new server object.
 *
 * @param server [out] Pointer to a buffer to store the server pointer. This
 * pointer must later be freed using @ref ksnp_server_destroy(). On error, NULL
 * is written instead.
 * @param ctx The message context to use for reading and writing message data.
 * The server does not take ownership of the context. Note that while this
 * server exists, the context should not be used for other purposes, as this may
 * corrupt message data.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_create(struct ksnp_server **server, struct ksnp_message_context *ctx) NOEXCEPT;

/**
 * @brief Destroy a previously created server object.
 *
 * @param server The server object to destroy, which must have been previously
 * created using @ref ksnp_server_create().
 */
void ksnp_server_destroy(struct ksnp_server *server) NOEXCEPT;

/**
 * @brief Check if the server is ready to receive more data.
 *
 * This function can be used to determine of the server does not have any data
 * available to process, and more input data is required, to be provided via
 * @ref ksnp_server_read_data(). This will always returns false once EOF has
 * been indicating using @ref ksnp_server_read_data().
 *
 * @param server The server to check.
 * @return true if no complete message is available for processing, and
 * @ref ksnp_server_read_data() should be called as soon as more data is
 * available.
 * @return false if some message data is available and @ref
 * ksnp_server_next_event() should be called as soon as possible.
 */
bool ksnp_server_want_read(struct ksnp_server const *server) NOEXCEPT;

/**
 * @brief Provide more data for the server to read.
 *
 * This function can be used to provide the server with further data received
 * from the client. The server buffers this data until it is ready to be
 * processed. To prevent this buffer from growing unduly (or filling up
 * entirely), the @ref ksnp_server_want_read() function should be used to
 * determine when it is appropriate to add more data.
 *
 * After calling this function, @ref ksnp_server_next_event() should be called
 * as soon as possible, or when @ref ksnp_server_want_read() returns false.
 *
 * To indicate the receiving channel from the client has been closed, i.e., EOF
 * was reached, the @p len parameter can be set to the value 0.
 *
 * @param server The server to provide data to.
 * @param data [optional] Pointer to a buffer containing more data. This can be
 * NULL @e only when @p len is 0.
 * @param len [in,out] Pointer to the length value, which must match the length
 * of the input buffer @p data, or be set to 0. When 0, the @p data parameter
 * may be NULL. If this function returns successfully, the number of bytes
 * actually read are written to the length value, which may be 0.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_read_data(struct ksnp_server *server, uint8_t const *data, size_t *len) NOEXCEPT;

/**
 * @brief Check if the server has data available to write.
 *
 * This function can be used to determine of the server has any data available
 * to send to the client, which can be read using @ref ksnp_server_write_data(). Data
 * normally becomes available during the initial handshake, after processing
 * input data, or after performing some stream operation.
 *
 * @param server The server to check.
 * @return true if data is available for writing, and @ref
 * ksnp_server_write_data() should be called as soon as the connection with the
 * client is willing to accept it.
 * @return false if no data is available to be written.
 */
bool ksnp_server_want_write(struct ksnp_server const *server) NOEXCEPT;

/**
 * @brief Receive data from the server to send to the client.
 *
 * This function can be used to receive the data from the server that needs to
 * be sent to the client. This is normally called when calling
 * @ref ksnp_server_want_write() returns true. The server buffers this data
 * until it is extracted. To prevent this buffer from growing unduly (or filling
 * up entirely), the @ref ksnp_server_want_write() function should be used to
 * determine when it is appropriate to send further data.
 *
 * @param server The server to read data from.
 * @param data [out] Pointer to a buffer to write data to.
 * @param len [in,out] Pointer to the length value, which must match the length
 * of the output buffer. If this function returns successfully, the number of
 * bytes actually written are written to the length value, which may be 0.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_write_data(struct ksnp_server *server, uint8_t *data, size_t *len) NOEXCEPT;

/**
 * @brief Process received data.
 *
 * This function will processed the received data, reading all incoming messages
 * until either no further messages can be processed, or an event has occurred
 * that needs to be responded to.
 *
 * Most often, this function can be called right after @ref
 * ksnp_server_read_data() was called, or immediately after handling an event
 * returned by a previous call to this function.
 *
 * Processing data may optionally result in an event. If it does, the caller
 * should handle the event as appropriate, and call this function again.
 * Otherwise, no further events will become available until further data has
 * been read or written.
 *
 * The data in the resulting event is valid only until the next call to this
 * function, @ref ksnp_server_read_data() or @ref ksnp_server_destroy().
 *
 * Calling this function may result in output data being generated, which can be
 * tested for using @ref ksnp_server_want_write().
 *
 * @param server The server to get the next event of.
 * @param event [out] Pointer to a buffer to store event data. This data is
 * valid only if this function returns successfully.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_next_event(struct ksnp_server *server, struct ksnp_server_event *event) NOEXCEPT;

/**
 * @brief Retrieve a pointer to the currently associated stream, if any.
 *
 * This function can be used to retrieve a pointer to the associated stream. The
 * pointer may be used until the next function that uses the server is called.
 * Any of the members defined for the @ref ksnp_stream struct may not be
 * modified.
 *
 * @param server Server to get the current stream from.
 * @return Pointer to the associated stream.
 * @return NULL if no stream is associated.
 */
struct ksnp_stream *ksnp_server_current_stream(struct ksnp_server const *server) NOEXCEPT;

/**
 * @brief Open a stream.
 *
 * This function may be called to open a stream in response to a
 * @ref ksnp_server_event_open_stream event. It is used when a stream could
 * successfully be opened.
 *
 * @param server Server that opens a new stream.
 * @param stream Stream to associate with the server. The server will not own
 * the stream, however it keeps a reference to it until the stream is closed or
 * suspended. Its public members should not be modified as long as the server
 * holds a reference to it.
 * @param params Stream parameters to send to the client.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_open_stream_ok(struct ksnp_server                       *server,
                                                struct ksnp_stream                       *stream,
                                                struct ksnp_stream_accepted_params const *params) NOEXCEPT;

/**
 * @brief Indicate failure to open a stream.
 *
 * This function may be called to indicate failure to open a stream in response
 * to a @ref ksnp_server_event_open_stream event.
 *
 * @param server Server that rejects a stream open request.
 * @param reason Code indicating the reason the stream could not be opened.
 * @param params [optional] QoS parameters to send if the stream could not be
 * opened due to the QoS constraints specified in the request.
 * @param message [optional] Message to send to the client to indicate the
 * reason the stream could not be opened.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_open_stream_fail(struct ksnp_server                  *server,
                                                  ksnp_status_code                     reason,
                                                  struct ksnp_stream_qos_params const *params,
                                                  char const                          *message) NOEXCEPT;

/**
 * @brief Close the associated stream.
 *
 * This function can be called in response to the @ref
 * ksnp_server_event_close_stream event, or some other external event.
 *
 * @param server Server that closes its stream.
 * @param stream [out] Pointer to receive the pointer to the associated stream.
 * This pointer takes ownership of the stream.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. A
 * previously associated stream is destroyed.
 */
NODISCARD ksnp_error ksnp_server_close_stream(struct ksnp_server *server, struct ksnp_stream **stream) NOEXCEPT;

/**
 * @brief Suspend the associated stream.
 *
 * This function can be called in response to the
 * @ref ksnp_server_event_suspend_stream event, or some other external event.
 *
 * @param server Server that suspends its stream.
 * @param timeout Time in seconds the stream will remain suspended for as long
 * the the client does not attempt to interact with it.
 * @param stream [out] Pointer to receive the pointer to the associated stream.
 * This pointer takes ownership of the stream.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. A previously
 * associated stream remains associated.
 */
NODISCARD ksnp_error ksnp_server_suspend_stream_ok(struct ksnp_server  *server,
                                                   uint32_t             timeout,
                                                   struct ksnp_stream **stream) NOEXCEPT;

/**
 * @brief Indicate failure to suspend a stream.
 *
 * This function may be called to indicate failure to suspend a stream in
 * response to a @ref ksnp_server_event_suspend_stream event.
 *
 * @param server Server that rejects to suspend its stream.
 * @param reason Code indicating the reason the stream could not be suspended.
 * @param message [optional] Message to send to the client to indicate the
 * reason the stream could not be suspended.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_suspend_stream_fail(struct ksnp_server *server,
                                                     ksnp_status_code    reason,
                                                     char const         *message) NOEXCEPT;

/**
 * @brief Indicate a keep alive request was successfully handled.
 *
 * This function may be called to indicate a keep alive in response to a
 * @ref ksnp_server_event_keep_alive event was successful.
 *
 * @param server Server that accepts a keep alive.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_keep_alive_ok(struct ksnp_server *server) NOEXCEPT;

/**
 * @brief Indicate failure to keep alive a suspended stream.
 *
 * This function may be called to indicate failure to keep alive a stream in
 * response to a @ref ksnp_server_event_keep_alive event.
 *
 * @param server Server that rejects a keep alive.
 * @param reason Code indicating the reason the keep alive could not be applied.
 * @param message [optional] Message to send to the client to indicate the
 * reason the stream could not be kept alive.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_keep_alive_fail(struct ksnp_server *server,
                                                 ksnp_status_code    reason,
                                                 char const         *message) NOEXCEPT;

/**
 * @brief Enter connection shutdown.
 *
 * Prepare to close the connection to the client. The server will accept
 * incoming data until the client closes the connection, but will not generate
 * any data to write. After calling this function, the outgoing connection must
 * be closed as soon as @ref ksnp_server_want_write() returns false.
 *
 * Any ongoing event is cancelled, and the server should read events until the
 * client has closed the connection.
 *
 * @param server The server for which to enter shutdown.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_server_close_connection(struct ksnp_server *server) NOEXCEPT;

// NOLINTEND(modernize-use-trailing-return-type)

#include "ksnp/compat.h"
