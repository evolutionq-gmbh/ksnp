/**
 * @file messages.h
 * @copyright Copyright 2025 evolutionQ GmbH. Licensed under the BSD-3-Clause
 * license, see LICENSE.
 *
 * @brief This header defines the various message types that are used by the
 * message context.
 */

#pragma once

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#include <json-c/json.h>
#include <uuid/uuid.h>

#include "ksnp/types.h"

#include "ksnp/compat.h"

// NOLINTBEGIN(hicpp-avoid-c-arrays, cppcoreguidelines-avoid-c-arrays, performance-enum-size)

/**
 * @brief Maximum length of a message in bytes, including header.
 */
static size_t const KSNP_MAX_MSG_LEN = UINT16_MAX;

/// @brief Size of the message header. Message header is 4 bytes; 2 type, 2 len
static size_t const KSNP_MSG_HEADER_SIZE = 4;

/**
 * @brief Supported message type variants.
 *
 * Any message sent or received must use a type from this enumeration. This
 * enumeration is also used for the @ref ksnp_message type.
 */
ENUM_TYPE(ksnp_message_type, uint16_t){
    KSNP_MSG_ERROR                   = 0,
    KSNP_MSG_VERSION                 = 1,
    KSNP_MSG_OPEN_STREAM             = 2,
    KSNP_MSG_OPEN_STREAM_REPLY       = 3,
    KSNP_MSG_CLOSE_STREAM            = 4,
    KSNP_MSG_CLOSE_STREAM_REPLY      = 5,
    KSNP_MSG_CLOSE_STREAM_NOTIFY     = 6,
    KSNP_MSG_SUSPEND_STREAM          = 7,
    KSNP_MSG_SUSPEND_STREAM_REPLY    = 8,
    KSNP_MSG_SUSPEND_STREAM_NOTIFY   = 9,
    KSNP_MSG_KEEP_ALIVE_STREAM       = 10,
    KSNP_MSG_KEEP_ALIVE_STREAM_REPLY = 11,
    KSNP_MSG_CAPACITY_NOTIFY         = 12,
    KSNP_MSG_KEY_DATA_NOTIFY         = 13,
};

/// @brief Concrete type for @ref ksnp_message_type.
ENUM_TYPE_T(ksnp_message_type, uint16_t);

/**
 * @brief An error message.
 */
struct ksnp_msg_error {
    /// @brief Error that occurred.
    ksnp_error_code code;
};

/**
 * @brief A version message.
 */
struct ksnp_msg_version {
    /// @brief The minimum supported version.
    ksnp_protocol_version minimum_version;
    /// @brief The maximum supported version.
    ///
    /// This must be greater or equal than `minimum_version`.
    ksnp_protocol_version maximum_version;
};

/**
 * @brief The open stream message.
 *
 * This message is sent by the client to open a new key stream. It is required
 * to send the stream parameters as a JSON object.
 */
struct ksnp_msg_open_stream {
    /// @brief The parameters that specify how the stream is to be configured.
    struct ksnp_stream_open_params const *parameters;
};

/**
 * @brief The open stream reply message.
 *
 * This message is sent by the server in response to an open stream message. If
 * the operation was successful, the @a code member is zero and the @a
 * parameters members contains the stream parameters. Otherwise, @a code is
 * nonzero and the @a message member may contain the reason for failure. If the
 * problem is due to unsatisfiable QoS parameters, the @a parameters member may
 * contain information about that.
 */
struct ksnp_msg_open_stream_reply {
    /// @brief Status code indicating either success or the reason for failure.
    ksnp_status_code               code;
    /// @brief Parameters for the opened stream or details about unsatisfiable
    /// QoS parameters.
    ///
    /// This member is optional for failed requests, but may be set if the
    /// request failed because of unsatisfiable QoS parameters.
    union ksnp_stream_reply_params parameters;
    /// @brief Optional message indicating the reason for failure if the @a code
    /// member is nonzero.
    char const                    *message;
};

/**
 * @brief The close stream message.
 *
 * This message is sent by the client to close an open stream.
 */
struct ksnp_msg_close_stream {
    unsigned char unused[1];
};

/**
 * @brief Those close stream reply message.
 *
 * This message is sent by the server in response to the close stream message.
 */
struct ksnp_msg_close_stream_reply {
    unsigned char unused[1];
};

/**
 * @brief The close stream notify message.
 *
 * This message is sent by the server if it closes the stream of its own accord.
 */
struct ksnp_msg_close_stream_notify {
    /// @brief Status code indicating the reason for closing the stream.
    ksnp_status_code code;
    /// @brief Optional message indicating the reason for closing the stream.
    char const      *message;
};

/**
 * @brief The suspend stream message.
 *
 * This message is sent by the client to suspend the open stream. It contains a
 * @a timeout parameter that indicates how long the stream should remain
 * suspended without further interaction from the client.
 */
struct ksnp_msg_suspend_stream {
    /// @brief Time in seconds to keep the stream suspended without reopening
    /// the stream or sending a keep alive.
    uint32_t timeout;
};

/**
 * @brief The suspend stream reply message.
 *
 * This message is sent by the server in response to the suspend stream message.
 * If the stream was successfully suspended, the @a code member is zero. It
 * contains a @a timeout member that indicates how long the stream will remain
 * suspended without further interaction from the client.
 */
struct ksnp_msg_suspend_stream_reply {
    /// @brief Status code indicating either success or the reason for failure.
    ksnp_status_code code;
    /// @brief The time in seconds the stream will remain suspended for if the
    /// operation was successful.
    uint32_t         timeout;
    /// @brief Optional message indicating the reason for failure if the @a code
    /// member is nonzero.
    char const      *message;
};

/**
 * @brief The close stream notify message.
 *
 * This message is sent by the server if it suspends the stream of its own
 * accord. It contains a @a timeout member that indicates how long the stream
 * will remain suspended without further interaction from the client.
 */
struct ksnp_msg_suspend_stream_notify {
    /// @brief The reason for suspending the stream.
    ksnp_status_code code;
    /// @brief The time in seconds the stream will remain suspended for before
    /// the server will close the stream.
    uint32_t         timeout;
};

/**
 * @brief The keep alive stream message.
 *
 * This message is sent by the client to keep a suspended stream available by
 * resetting the timeout to the previously agreed value.
 */
struct ksnp_msg_keep_alive_stream {
    /// @brief The key stream ID of the stream to keep suspended.
    uuid_t key_stream_id;
};

/**
 * @brief The keep alive stream reply message.
 *
 * The message is sent by the server in response to the keep alive message.
 */
struct ksnp_msg_keep_alive_stream_reply {
    /// @brief Status code indicating either success or the reason for failure.
    ksnp_status_code code;
    /// @brief Optional message indicating the reason for failure if the @a code
    /// member is nonzero.
    char const      *message;
};

/**
 * @brief The capacity notify message.
 *
 * This message is sent by the client to indicate it has further capacity for
 * receiving key data.
 */
struct ksnp_msg_capacity_notify {
    /// @brief The additional capacity in bytes available at the client for key
    /// data.
    uint32_t additional_capacity;
};

/**
 * @brief The key data notify message.
 *
 * This message is sent by the server to transfer key data associated with the
 * open key stream.
 *
 * Key data is always transferred in multiples of the agreed-upon chunk size.
 * Vendor-specific extensions may be associated with the key data as part of the
 * @a parameters member.
 */
struct ksnp_msg_key_data_notify {
    /// @brief The key data that was transferred.
    struct ksnp_data    key_data;
    /// @brief Optional parameters associated with the key data.
    struct json_object *parameters;
};

/**
 * @brief Union of all possible messages sent between a client and server.
 *
 * This is a basic tagged union, where the @a type member determines which of
 * the (anonymous) union's fields is set.
 */
struct ksnp_message {
    /// @brief Type of the message.
    ///
    /// Must be a value from the @ref ksnp_message_type enumeration. This
    /// determines the union member used.
    ksnp_message_type type;
    /// @brief Message payload.
    ///
    /// The member set is determined by the @a type member.
    union {
        struct ksnp_msg_error                   error;
        struct ksnp_msg_version                 version;
        struct ksnp_msg_open_stream             open_stream;
        struct ksnp_msg_open_stream_reply       open_stream_reply;
        struct ksnp_msg_close_stream            close_stream;
        struct ksnp_msg_close_stream_reply      close_stream_reply;
        struct ksnp_msg_close_stream_notify     close_stream_notify;
        struct ksnp_msg_suspend_stream          suspend_stream;
        struct ksnp_msg_suspend_stream_reply    suspend_stream_reply;
        struct ksnp_msg_suspend_stream_notify   suspend_stream_notify;
        struct ksnp_msg_keep_alive_stream       keep_alive_stream;
        struct ksnp_msg_keep_alive_stream_reply keep_alive_stream_reply;
        struct ksnp_msg_capacity_notify         capacity_notify;
        struct ksnp_msg_key_data_notify         key_data_notify;
    };
};

// NOLINTEND(hicpp-avoid-c-arrays, cppcoreguidelines-avoid-c-arrays, performance-enum-size)

#include "ksnp/compat.h"
