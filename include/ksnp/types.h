/**
 * @file types.h
 * @copyright Copyright 2025 evolutionQ GmbH. Licensed under the BSD-3-Clause
 * license, see LICENSE.
 *
 * @brief Common types for key stream protocol functions.
 */

#pragma once

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#include <json-c/json.h>
#include <uuid/uuid.h>

#include "ksnp/compat.h"

// NOLINTBEGIN(modernize-use-trailing-return-type, bugprone-macro-parentheses,
// cppcoreguidelines-macro-usage, performance-enum-size)

/// @brief Maximum size of key chunks.
///
/// This 2^15, as to fit in a u16 with some room for message header data.
static uint16_t const KSNP_MAX_CHUNK_SIZE = 1 << (16 - 1);

/**
 * @enum ksnp_error
 * @brief Type for errors that may be returned by KSNP functions.
 */
ENUM_TYPE(ksnp_error, unsigned int)
/*NOLINT(performance-enum-size)*/ {
    /// @brief No error occurred.
    KSNP_E_NO_ERROR = 0,
    /// @brief Some unspecified error occurred.
    KSNP_E_UNKNOWN,
    /// @brief Failed to allocate memory.
    KSNP_E_NO_MEM,
    /// @brief A protocol violation has occurred.
    KSNP_E_PROTOCOL_ERROR,
    /// @brief Serialization failed: message length exceeds limit.
    KSNP_E_SER_MSG_TOO_LARGE,
    /// @brief Serialization failed: JSON payload size exceeds limit.
    KSNP_E_SER_JSON_TOO_LARGE,
    /// @brief The version sent by the client is not supported.
    KSNP_E_UNSUPPORTED_VERSION,
    /// @brief An operation was performed that is not allowed by the current
    /// state of the server or client.
    KSNP_E_INVALID_OPERATION,
    /// @brief A function was called with an invalid parameter value.
    KSNP_E_INVALID_ARGUMENT,
    /// @brief A key stream returned more data than was permissible.
    KSNP_E_KEY_DATA_TOO_LARGE,
    /// @brief A key stream uses a chunk size that is too large.
    KSNP_E_CHUNK_SIZE_TOO_LARGE,
    /// @brief A message with an invalid type was used.
    KSNP_E_INVALID_MESSAGE_TYPE,
    /// @brief An event with an invalid type was used.
    KSNP_E_INVALID_EVENT_TYPE,
};

/// @brief Concrete type for @ref ksnp_error.
ENUM_TYPE_T(ksnp_error, unsigned int);

/**
 * @enum ksnp_protocol_version
 * @brief Protocol variants.
 *
 * This is an enumeration of the protocol variants known to this library.
 */
ENUM_TYPE(ksnp_protocol_version, uint8_t){
    /// @brief Protocol version 1.
    PROTOCOL_V1 = 1,
};

/// @brief Concrete type for @ref ksnp_protocol_version.
ENUM_TYPE_T(ksnp_protocol_version, uint8_t);

/// @brief Type used for key stream IDs, which are UUIDs.
typedef uuid_t ksnp_key_stream_id;

/**
 * @brief Wrapper for arbitrary byte strings.
 */
struct ksnp_data {
    /// @brief Pointer to the data.
    ///
    /// This pointer may be NULL if @a len is 0.
    unsigned char const *data;
    /// @brief Length of the byte string.
    ///
    /// Although uncommon, this may be zero for empty buffers.
    size_t               len;
};

/**
 * @brief Stream address.
 *
 * An address identifies the source and destination for a key stream.
 */
struct ksnp_address {
    /// @brief Name of the SAE.
    char const *sae;
    /// @brief Identifier of the network. This member is optional.
    char const *network;
};

/**
 * @brief Data transfer rate.
 *
 * A transfer rate is used to specify the minimum and maximum transfer rates for
 * key streams.
 */
struct ksnp_rate {
    /// @brief Number of bits per unit of time, must be positive.
    uint32_t bits;
    /// @brief Unit of time in seconds. 0 is interpreted as the default value of
    /// 1.
    uint32_t seconds;
};

/**
 * @brief Parameters for a stream as used for the open stream message.
 *
 * If an instance of this struct is returned as part of a message by
 * next_message(), the message_context object retains ownership of the
 * instance, and the caller must not free any of its members.
 *
 * If an instance of this struct is passed to write_message, the
 * message_context object does NOT assume ownership of the instance. In this
 * case, it remains the caller's responsibility to free any resources after the
 * operation concluded.
 */
struct ksnp_stream_open_params {
    /// @brief Stream ID. The nil (all-zero) value means no stream ID is
    /// provided.
    ksnp_key_stream_id  stream_id;
    /// @brief Stream source address. If both fields are NULL pointers, this
    /// member is considered not set.
    struct ksnp_address source;
    /// @brief Stream target address. This member's SAE field is required.
    struct ksnp_address destination;
    /// @brief Key data chunk size. 0 means no chunk size is specified.
    uint16_t            chunk_size;
    /// @brief Initial key data capacity of the client.
    uint32_t            capacity;
    /// @brief Minimum desired key transfer rate. A rate with all fields 0 means
    /// no rate is specified.
    struct ksnp_rate    min_bps;
    /// @brief Maximum supported key transfer rate. A rate with all fields 0
    /// means no rate is specified.
    struct ksnp_rate    max_bps;
    /// @brief Maximum age of key data in seconds. 0 means no TTL is specified.
    uint32_t            ttl;
    /// @brief Minimum desired buffer capacity for the server.
    uint32_t            provision_size;
    /// @brief Optional vendor extensions. This member is optional.
    struct json_object *extensions;
    /// @brief Required vendor extensions. This member is optional.
    struct json_object *required_extensions;
};

/**
 * @brief Parameters for a stream as used for the open stream reply message.
 *
 * If an instance of this struct is returned as part of a message by
 * next_message(), the message_context object retains ownership of the
 * instance, and the caller must not free any of its members.
 *
 * If an instance of this struct is passed to write_message, the
 * message_context object does NOT assume ownership of the instance. In this
 * case, it remains the caller's responsibility to free any resources after the
 * operation concluded.
 */
struct ksnp_stream_accepted_params {
    /// @brief KSID of the opened stream. The nil (all-zero) value means no
    /// stream ID is provided.
    ksnp_key_stream_id  stream_id;
    /// @brief Size of integral keys that the server provides. 0 means no chunk
    /// size is specified.
    uint16_t            chunk_size;
    /// @brief Current position in the key stream. The client can use this to
    /// synchronize with another client when resuming a suspended stream.
    uint32_t            position;
    /// @brief Expected maximum time in seconds between delivered keys. 0 means
    /// no max time is specified.
    uint32_t            max_key_delay;
    /// @brief Minimum desired key transfer rate. A rate with all fields 0 means
    /// no rate is specified.
    struct ksnp_rate    min_bps;
    /// @brief Actual reserved buffer capacity for the server. 0 means no
    /// provision size is specified.
    uint32_t            provision_size;
    /// @brief Vendor extensions. This member is optional.
    struct json_object *extensions;
};

/**
 * @brief Enumeration of QoS parameter variants.
 *
 * This enumeration is used to indicate which field is set in any of the @a
 * qos_t unions.
 */
ENUM_TYPE(ksnp_qos_type, uint8_t){

    /// @brief No value is present.
    ///
    /// A field of this type is unset.
    KSNP_QOS_NONE,
    /// @brief The null value is present.
    ///
    /// A field of this type indicates the server does not accept any request
    /// for the corresponding field.
    KSNP_QOS_NULL,
    ///@brief The @p range member is present.
    ///
    /// A field of this type indicates the server accepts any value between the
    /// min and max values of the range for the corresponding field.
    KSNP_QOS_RANGE,
    ///@brief The @p list member is present.
    ///
    /// A field of this type indicates the server accepts any of the listed
    /// values for the corresponding field.
    KSNP_QOS_LIST};

/// @brief Concrete type for @ref ksnp_qos_type.
ENUM_TYPE_T(ksnp_qos_type, uint8_t);

/// @brief Type name for a QoS range.
#define QOS_RANGE_T(T) struct ksnp_qos_range_##T

/// @brief Generates a definition for a QoS range.
#define QOS_RANGE_DEF(N, T) \
    QOS_RANGE_T(N)          \
    {                       \
        T min;              \
        T max;              \
    }

/// @brief Type name for a QoS list.
#define QOS_LIST_T(N) struct ksnp_qos_list_##N

/// @brief Generates a definition for a QoS list.
#define QOS_LIST_DEF(N, T) \
    QOS_LIST_T(N)          \
    {                      \
        T const *values;   \
        size_t   count;    \
    }

/// @brief Type name for a QoS parameter.
#define QOS_T(T) struct ksnp_qos_##T

/// @brief Generates a definition for a QoS parameter.
#define QOS_DEF(N, T)             \
    QOS_RANGE_DEF(N, T);          \
    QOS_LIST_DEF(N, T);           \
    QOS_T(N)                      \
    {                             \
        ksnp_qos_type type;       \
        union {                   \
            int none;             \
            QOS_RANGE_T(N) range; \
            QOS_LIST_T(N) list;   \
        };                        \
    }

/**
 * @brief A uint16_t based QoS parameter.
 */
QOS_DEF(u16, uint16_t);

/**
 * @brief A uint32_t based QoS parameter.
 */
QOS_DEF(u32, uint32_t);

/**
 * @brief A rate based QoS parameter.
 */
QOS_DEF(rate, struct ksnp_rate);

#undef QOS_DEF
#undef QOS_T
#undef QOS_RANGE_T
#undef QOS_RANGE_DEF
#undef QOS_LIST_T
#undef QOS_LIST_DEF

/**
 * @brief Reply parameters for an open stream message if at least one of the
 * QoS parameters could not be fulfilled.
 *
 * If an instance of this struct is returned as part of a message by
 * next_message(), the message_context object retains ownership of the
 * instance, and the caller must not free any of its members.
 *
 * If an instance of this struct is passed to write_message, the
 * message_context object does NOT assume ownership of the instance. In this
 * case, it remains the caller's responsibility to free any resources after the
 * operation concluded.
 */
struct ksnp_stream_qos_params {
    /// @brief Size of integral keys the server supports.
    struct ksnp_qos_u16  chunk_size;
    /// @brief Minimum desired key transfer rate the server can provide.
    struct ksnp_qos_rate min_bps;
    /// @brief Maximum age of key data in seconds the server supports.
    struct ksnp_qos_u32  ttl;
    /// @brief Buffer capacity for key data the server can provide.
    struct ksnp_qos_u32  provision_size;
    /// @brief Vendor extensions. This member is optional.
    struct json_object  *extensions;
};

/**
 * @brief Union of possible parameter data for stream open reply messages.
 *
 * For successful operations, the stream_accepted_params type is used, otherwise
 * stream_qos_params.
 */
union ksnp_stream_reply_params {
    /// @brief Parameters for an opened stream.
    struct ksnp_stream_accepted_params const *reply;
    /// @brief [optional] Parameters for a QoS error.
    ///
    /// This member is set for stream open replies with a non-zero status. It
    /// may however be NULL.
    struct ksnp_stream_qos_params const      *qos;
};

/**
 * @enum ksnp_close_direction
 * @brief Enumeration of possible directions for a close operation.
 */
ENUM_TYPE(ksnp_close_direction, uint8_t){
    /// @brief The read direction is closed.
    KSNP_CLOSE_READ  = 1,
    /// @brief The write direction is closed.
    KSNP_CLOSE_WRITE = 2,
    /// @brief Both read and write directions are closed.
    KSNP_CLOSE_BOTH  = 3,
};

/// @brief Alias for @ref ksnp_close_direction.
ENUM_TYPE_T(ksnp_close_direction, uint8_t);

/**
 * @enum ksnp_error_code
 * @brief Enumeration of possible protocol errors that may be sent as part of
 * an error message.
 */
ENUM_TYPE(ksnp_error_code, uint32_t){
    /// @brief Error of unknown origin.
    KSNP_PROT_E_UNKNOWN_ERROR      = 0,
    /// @brief A message was sent in violation of the protocol.
    KSNP_PROT_E_UNEXPECTED_MESSAGE = 1,
    /// @brief The client reports more capacity than the protocol allows for.
    KSNP_PROT_E_EXCESSIVE_CAPACITY = 2,
    /// @brief The server sent a chunk that is not a multiple of the chunk size.
    KSNP_PROT_E_INVALID_CHUNK      = 3,
    /// @brief The connection is being closed due to a timeout.
    KSNP_PROT_E_TIMEOUT            = 4,
    /// @brief Message type not supported.
    KSNP_PROT_E_BAD_MSG_TYPE       = 5,
    /// @brief Message length not within bounds.
    KSNP_PROT_E_BAD_MSG_LENGTH     = 6,
    /// @brief Deserialization failed: JSON object missing from message.
    KSNP_PROT_E_JSON_MISSING       = 7,
    /// @brief Deserialization failed: corrupt JSON data.
    KSNP_PROT_E_BAD_JSON           = 8,
    /// @brief Deserialization failed: unexpected JSON object type.
    KSNP_PROT_E_BAD_JSON_TYPE      = 9,
    /// @brief Deserialization failed: unexpected JSON data length.
    KSNP_PROT_E_BAD_JSON_LENGTH    = 10,
    /// @brief Deserialization failed: required JSON key missing.
    KSNP_PROT_E_JSON_KEY_MISSING   = 11,
    /// @brief Deserialization failed: unexpected JSON key.
    KSNP_PROT_E_BAD_JSON_KEY       = 12,
    /// @brief Deserialization failed: invalid JSON value.
    KSNP_PROT_E_BAD_JSON_VAL       = 13,
    /// @brief An incomplete message has been received, but the receiving
    /// channel is closed.
    KSNP_PROT_E_INCOMPLETE_MSG     = 14,
};

/// @brief Alias for @ref ksnp_error_code.
ENUM_TYPE_T(ksnp_error_code, uint32_t);

/**
 * @enum ksnp_status_code
 * @brief Enumeration of possible status codes that may be sent as part of
 * reply or notify messages.
 */
ENUM_TYPE(ksnp_status_code, uint32_t){
    /// @brief The operation completed successfully.
    KSNP_STATUS_SUCCESS                 = 0,
    /// @brief Could not satisfy one or more requested parameters.
    KSNP_STATUS_INVALID_PARAMETER       = 1,
    /// @brief This implementation does not support the requested operation.
    KSNP_STATUS_OPERATION_NOT_SUPPORTED = 2,
    /// @brief Closing or suspending stream due to corresponding action by
    /// peer.
    KSNP_STATUS_NOTIFY_DUE_TO_PEER      = 3,
};

/// @brief Alias for @ref ksnp_status_code.
ENUM_TYPE_T(ksnp_status_code, uint32_t);

/**
 * @brief Description for a protocol error when detected by the message parser.
 *
 * This type is used by @ref ksnp_message_context_next_message() to provide the
 * cause for a protocol error.
 */
struct ksnp_protocol_error {
    /// @brief Code indicating the cause for the protocol error.
    ksnp_error_code code;
    /// @brief Optional human readable description of the reason of the error.
    /// This pointer, if not NULL, is valid until the next operation is
    /// performed on the message context from which this event originates.
    char const     *description;
};

/**
 * @brief Get a description for an API error.
 *
 * This function can be used to get a human readable description for a failed
 * API operation.
 *
 * @param error The error to get a description for. This must be a value
 * returned from one of the API functions.
 * @return A pointer to a static string with the description.
 */
char const *ksnp_error_description(ksnp_error error);

/**
 * @brief Get a description for a message status code.
 *
 * This function can be used to get a human readable description for a known
 * status code.
 *
 * @param code The status code to get a description for.
 * @return A pointer to a static string with the description.
 * @return NULL if the status code is not known.
 */
char const *ksnp_status_code_description(ksnp_status_code code);

/**
 * @brief Get a description for a protocol error code.
 *
 * This function can be used to get a human readable description for a known
 * protocol error.
 *
 * @param code The protocol error to get a description for.
 * @return A pointer to a static string with the description.
 * @return NULL if the protocol error is not known.
 */
char const *ksnp_protocol_error_description(ksnp_error_code code);

// NOLINTEND(modernize-use-trailing-return-type, bugprone-macro-parentheses, cppcoreguidelines-macro-usage,
// performance-enum-size)

#include "ksnp/compat.h"
