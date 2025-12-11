/**
 * @file client.h
 * @copyright Copyright 2025 evolutionQ GmbH. Licensed under the BSD-3-Clause
 * license, see LICENSE.
 *
 * @brief Handling the client state machine for key stream connections.
 *
 * This header defines the types and functions for handling the client state
 * machine for a single client connection, primarily @ref ksnp_client.
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

#include <json-c/json.h>

#include "ksnp/types.h"

#include "ksnp/compat.h"

// NOLINTBEGIN(modernize-use-trailing-return-type)

struct ksnp_message_context;

/**
 * @brief Enumeration of possible event types that can be set in the
 * @ref ksnp_client_event struct.
 */
ENUM_TYPE(ksnp_client_event_type, uint8_t){
    /// @brief No event has occurred.
    KSNP_CLIENT_EVENT_NONE,
    /// @brief The @a handshake event.
    KSNP_CLIENT_EVENT_HANDSHAKE,
    /// @brief The @a open_stream event.
    KSNP_CLIENT_EVENT_STREAM_OPEN,
    /// @brief The @a close_stream event.
    KSNP_CLIENT_EVENT_STREAM_CLOSE,
    /// @brief The @a suspend_stream event.
    KSNP_CLIENT_EVENT_STREAM_SUSPEND,
    /// @brief The @a new_capacity event.
    KSNP_CLIENT_EVENT_STREAM_KEY_DATA,
    /// @brief The @a keep_alive event.
    KSNP_CLIENT_EVENT_KEEP_ALIVE,
    /// @brief The @a error event.
    KSNP_CLIENT_EVENT_ERROR,
};

/// @brief Concrete type for @ref ksnp_client_event_type.
ENUM_TYPE_T(ksnp_client_event_type, uint8_t);

/**
 * @brief Event indicating the initial handshake has completed.
 *
 * This event is sent if the handshake has completed and the protocol version
 * has been established.
 */
struct ksnp_client_event_handshake {
    /// @brief The agreed upon protocol version.
    ksnp_protocol_version protocol;
};

/**
 * @brief Event indicating the server has responded to an open stream message.
 *
 * If the stream was successfully opened, the @p code member is zero and the
 * stream's details are available in @p parameters. Otherwise, code is nonzero
 * and the @p message may optionally contain the reason for failure.
 *
 */
struct ksnp_client_event_stream_open {
    /// @brief Result code for the open stream message.
    ksnp_status_code               code;
    /// @brief Parameters for the opened stream.
    ///
    /// If the stream could not be opened due to a QoS limitation, this value
    /// may optionally be set and be used to determine the cause for failure.
    union ksnp_stream_reply_params parameters;
    /// @brief Status message for nonzero status codes.
    ///
    /// This field is optional, and contains a C-string if set.
    char const                    *message;
};

/**
 * @brief Event indicating the server has closed the stream.
 *
 * This event may be triggered to stream close replies or notifications. When
 * the server closes the stream by notification, the @p code and @p message
 * fields may be used.
 */
struct ksnp_client_event_stream_close {
    /// @brief Result code for stream close notifications.
    ///
    /// This field is used by the server when it sends a stream close
    /// notification, otherwise it is always zero.
    ksnp_status_code code;
    /// @brief Status message for nonzero status codes.
    ///
    /// This field is optional, and contains a C-string if set.
    char const      *message;
};

/**
 * @brief Event indicating the server has responded to a suspend request or has
 * suspended the stream.
 */
struct ksnp_client_event_stream_suspend {
    /// @brief Result code for suspend operations.
    ///
    /// A nonzero value with a @p timeout of zero means a suspend request
    /// failed. A nonzero value with a nonzero @p timeout means the stream was
    /// suspended by the server.
    ksnp_status_code code;
    /// @brief Timeout for the suspended stream.
    ///
    /// This is the timeout set by the server, and may deviate from a request,
    /// if there was any.
    uint32_t         timeout;
    /// @brief Status message for nonzero status codes.
    ///
    /// This field is optional, and contains a C-string if set.
    char const      *message;
};

/**
 * @brief  Event indicating new key data has arrived on the open stream.
 *
 * This event occurs as a result of the server sending key data.
 */
struct ksnp_client_event_key_data {
    /// @brief Buffer for the key data.
    struct ksnp_data   key_data;
    /// @brief Optional parameters for the key data. If set, these are always
    /// vendor extensions.
    json_object const *parameters;
};

/**
 * @brief Event indicating the server has responded to a keep alive message.
 *
 * This event occurs as a result of the client sending a keep alive message. If
 * the request succeeded, the @p code member is zero, otherwise it is nonzero.
 */
struct ksnp_client_event_keep_alive {
    /// @brief Result code for the keep alive operation.
    ksnp_status_code code;
    /// @brief Status message for nonzero status codes.
    ///
    /// This field is optional, and contains a C-string if set.
    char const      *message;
};

/**
 * @brief Event indicating a protocol error has occurred.
 *
 * This event occurs as a result of either the client detecting a protocol
 * violation or the server sending a protocol violation error. The @a code
 * member contains the reason for the error.
 *
 * If this event is received, the client should not attempt to read further
 * data, send all remaining pending data and close the connection.
 */
struct ksnp_client_event_error {
    /// @brief Reason for the error.
    ksnp_error_code code;
    /// @brief Optional human readable description of the reason of the error.
    /// This pointer, if not NULL, is valid until the next operation is
    /// performed on the client from which this event originates.
    char const     *description;
};

/**
 * @brief Any event that may be triggered by the client processing server data.
 */
struct ksnp_client_event {
    /// @brief Type of the contained event, which determines which field of the
    /// union is set, and must be a value from the @ref ksnp_client_event_type
    /// enumeration.
    ksnp_client_event_type type;
    union {
        int                                     none;
        struct ksnp_client_event_handshake      handshake;
        struct ksnp_client_event_stream_open    stream_open;
        struct ksnp_client_event_stream_close   stream_close;
        struct ksnp_client_event_stream_suspend stream_suspend;
        struct ksnp_client_event_key_data       key_data;
        struct ksnp_client_event_keep_alive     keep_alive;
        struct ksnp_client_event_error          error;
    };
};

/**
 * @struct ksnp_client
 * @brief A type for managing the protocol state machine and messages for client
 * connections.
 *
 * This type can be used to read and write message data for a client, and ensure
 * the protocol is followed correctly.
 *
 * A client can be created using @ref ksnp_client_create(). To use it, data must
 * be read and written using @ref ksnp_client_read_data() and @ref
 * ksnp_client_write_data(), which respectively read received server data and
 * write data to send to the server.
 *
 * After receiving data from the server, @ref ksnp_client_next_event() should be
 * called as soon as possible to process the message data and handle the
 * corresponding events.
 *
 * To check if the client requires more data from the server, or has data to
 * send to the server, the @ref ksnp_client_want_read() and @ref ksnp_client_want_write()
 * functions can be used. If either of these returns true, the
 * @ref ksnp_client_read_data() and @ref ksnp_client_write_data() functions
 * should be called as appropriate.
 *
 * This type cannot be used concurrently across threads, but can be shared
 * between threads.
 */
struct ksnp_client;

/**
 * @brief Create a new client object.
 *
 * @param client [out] Pointer to a buffer to store the client pointer. This
 * pointer must later be freed using @ref ksnp_client_destroy().
 * @param ctx The message context to use for reading and writing message data.
 * The client does not take ownership of the context. Note that while this
 * client exists, the context should not be used for other purposes, as this may
 * corrupt message data.
 * On error, NULL is written instead.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_client_create(struct ksnp_client **client, struct ksnp_message_context *ctx) NOEXCEPT;

/**
 * @brief Destroy a previously created client object.
 *
 * @param client The client object to destroy, which must have been previously
 * created using @ref ksnp_client_create().
 */
void ksnp_client_destroy(struct ksnp_client *client) NOEXCEPT;

/**
 * @brief Check if the client is ready to receive more data.
 *
 * This function can be used to determine of the client does not have any data
 * available to process, and more input data is required, to be provided via
 * @ref ksnp_client_read_data(). This will always returns false once EOF has
 * been indicating using @ref ksnp_client_read_data().
 *
 * @param client The client to check.
 * @return true if no complete message is available for processing, and
 * @ref ksnp_client_read_data() should be called as soon as more data is
 * available.
 * @return false if some message data is available and @ref ksnp_client_next_event()
 * should be called as soon as possible.
 */
bool ksnp_client_want_read(struct ksnp_client const *client) NOEXCEPT;

/**
 * @brief Provide more data for the client to read.
 *
 * This function can be used to provide the client with further data received
 * from the server. The client buffers this data until it is ready to be
 * processed. To prevent this buffer from growing unduly (or filling up
 * entirely), the @ref ksnp_client_want_read() function should be used to
 * determine when it is appropriate to add more data.
 *
 * After calling this function, @ref ksnp_client_next_event() should be called
 * as soon as possible, or when @ref ksnp_client_want_read() returns false.
 *
 * To indicate the receiving channel from the server has been closed, i.e., EOF
 * was reached, the @p len parameter can be set to the value 0.
 *
 * @param client The client that is provided with more data.
 * @param data [optional] Pointer to a buffer containing more data. This can be
 * NULL \e only when @p len is 0.
 * @param len [in,out] Pointer to the length value, which must match the length
 * of the input buffer @p data, or be set to 0. When 0, the @p data parameter
 * may be NULL. If this function returns successfully, the number of bytes
 * actually read are written to the length value, which may be 0.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_client_read_data(struct ksnp_client *client, uint8_t const *data, size_t *len) NOEXCEPT;

/**
 * @brief Check if the client has data available to write.
 *
 * This function can be used to determine of the client has any data available
 * to send to the server, which can be read using @ref ksnp_client_write_data().
 * Data normally becomes available during the initial handshake, after
 * processing input data, or after performing some stream operation.
 *
 * @param client The client that is checked.
 * @return true if data is available for writing, and @ref
 * ksnp_client_write_data() should be called as soon as the connection with the
 * server is willing to accept it.
 * @return false if no data is available to be written.
 */
bool ksnp_client_want_write(struct ksnp_client const *client) NOEXCEPT;

/**
 * @brief Receive data from the client to send to the server.
 *
 * This function can be used to receive the data from the client that needs to
 * be sent to the server. This is normally called when calling
 * @ref ksnp_client_want_write() returns true. The client buffers this data
 * until it is extracted. To prevent this buffer from growing unduly (or filling
 * up entirely), the @ref ksnp_client_want_write() function should be used to
 * determine when it is appropriate to send further data.
 *
 * @param client The client to read data from.
 * @param data [out] Pointer to a buffer to write data to.
 * @param len [in,out] Pointer to the length value, which must match the length
 * of the output buffer. If this function returns successfully, the number of
 * bytes actually written are written to the length value, which may be 0.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_client_write_data(struct ksnp_client *client, uint8_t *data, size_t *len) NOEXCEPT;

/**
 * @brief Process received data.
 *
 * This function will processed the received data, reading all incoming messages
 * until either no further messages can be processed, or an event has occurred
 * that needs to be responded to.
 *
 * Most often, this function can be called right after @ref
 * ksnp_client_read_data() was called, or immediately after handling an event
 * returned by a previous call to this function.
 *
 * Processing data may optionally result in an event. If it does, the caller
 * should handle the event as appropriate, and call this function again.
 * Otherwise, no further events will become available until further data has
 * been read or written.
 *
 * The data in the resulting event is valid only until the next call to this
 * function, @ref ksnp_client_read_data() or @ref ksnp_client_destroy().
 *
 * Calling this function may result in output data being generated, which can be
 * tested for using @ref ksnp_client_want_write().
 *
 * @param client The client to get the next event of.
 * @param event [out] Pointer to a buffer to store event data. This data is
 * valid only if this function returns successfully.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_client_next_event(struct ksnp_client *client, struct ksnp_client_event *event) NOEXCEPT;

/**
 * @brief Request to open a new key stream.
 *
 * This function can be used to request a new key stream or reopen a suspended
 * stream on a connection without an associated key stream.
 *
 * The request is not complete until a @ref ksnp_client_event_stream_open
 * occurs, which contains the result of the request.
 *
 * @param client The client that requests to open a key stream.
 * @param parameters Parameters for the key stream.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. No open
 * request is sent in this case.
 */
NODISCARD ksnp_error ksnp_client_open_stream(struct ksnp_client                   *client,
                                             struct ksnp_stream_open_params const *parameters) NOEXCEPT;

/**
 * @brief Request to close the open stream.
 *
 * This function can be used to close the key stream currently open.
 *
 * The request is not complete until a @ref ksnp_client_event_stream_close
 * occurs.
 *
 * @param client The client that sends the close request.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. No close
 * request is sent in this case.
 */
NODISCARD ksnp_error ksnp_client_close_stream(struct ksnp_client *client) NOEXCEPT;

/**
 * @brief Request to suspend the open stream.
 *
 * This function can be used to request to suspend the key stream currently
 * open. The @p timeout parameter is used to indicate the desired minimum time
 * to keep the stream suspended for.
 *
 * The request is not complete until a @ref ksnp_client_event_stream_suspend
 * occurs, which contains the result of the request.
 *
 * @param client The client that sends the suspend request.
 * @param timeout Time in seconds to keep the stream suspended for. Note that
 * the server may choose a different timeout, which is returned in the
 * @ref ksnp_client_event_stream_suspend event.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. No
 * suspend request is sent in this case.
 */
NODISCARD ksnp_error ksnp_client_suspend_stream(struct ksnp_client *client, uint32_t timeout) NOEXCEPT;

/**
 * @brief Indicate further capacity for key data is available.
 *
 * This function can be used to indicate to the server further key data capacity
 * is available for the stream currently open.
 *
 * Note that the total available capacity may not exceed UINT32_MAX.
 *
 * @param client The client that sends the capacity notification.
 * @param additional_capacity Additional capacity in bytes that is available for
 * receiving key data.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. No
 * notification is sent in that case.
 */
NODISCARD ksnp_error ksnp_client_add_capacity(struct ksnp_client *client, uint32_t additional_capacity) NOEXCEPT;

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
 * @param client The client that sends the keep alive request.
 * @param stream_id The identifier of the key stream to keep alive.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. No
 * notification is sent in that case.
 */
NODISCARD ksnp_error ksnp_client_keep_alive(struct ksnp_client *client, ksnp_key_stream_id const *stream_id) NOEXCEPT;

/**
 * @brief Enter connection shutdown.
 *
 * Prepare to close the connection to the server. The client will accept
 * incoming data until the server closes the connection, but will not generate
 * any data to write. After calling this function, the outgoing connection must
 * be closed as soon as @ref ksnp_client_want_write() returns false.
 *
 * @param client The client for which to enter shutdown.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_client_close_connection(struct ksnp_client *client) NOEXCEPT;

// NOLINTEND(modernize-use-trailing-return-type)

#include "ksnp/compat.h"
