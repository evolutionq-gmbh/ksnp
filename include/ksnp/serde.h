/**
 * @file serde.h
 * @copyright Copyright 2025 evolutionQ GmbH. Licensed under the BSD-3-Clause
 * license, see LICENSE.
 *
 * @brief Common types serializing and deserializing message data. These
 * operations are available using the @ref ksnp_message_context type.
 */

#pragma once

#ifdef __cplusplus
#include <cstddef>
#else
#include <stdbool.h>
#include <stddef.h>
#endif

#include "ksnp/types.h"

#include "ksnp/compat.h"

// NOLINTBEGIN(modernize-use-trailing-return-type)

struct ksnp_message;

/**
 * @struct ksnp_message_context
 * @brief A type for serializing and deserializing protocol messages.
 *
 * A message context is used to buffer incoming data and outgoing data
 * and translate it to and from protocol messages.
 *
 * A message context can be created using @ref ksnp_message_context_create(). To
 * use it, data must be read and written using @ref
 * ksnp_message_context_read_data() and
 * @ref ksnp_message_context_write_data().
 *
 * After reading data, @ref ksnp_message_context_next_message() should be called
 * as soon as possible to process the message data and free up the input buffer.
 *
 * To check if the message context requires more data to read, or has data to
 * write, the @ref ksnp_message_context_want_read() and @ref
 * ksnp_message_context_want_write() functions can be used. If either of these
 * returns true, the @ref ksnp_message_context_read_data() and @ref
 * ksnp_message_context_write_data() functions should be called as appropriate.
 *
 * It is recommended to use this type in tandem with either @ref ksnp_server or
 * @ref ksnp_client, as these types handle the protocol state machines.
 *
 * This type cannot be used concurrently across threads, but can be shared
 * between threads.
 */
struct ksnp_message_context;

/**
 * @brief Create a new message context that can be used to serialize and
 * deserialize messages.
 *
 * @param context [out] Pointer to a buffer to store the created message context
 * pointer. This pointer must later be freed using @ref
 * ksnp_message_context_destroy(). On error, NULL is written instead.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
ksnp_error ksnp_message_context_create(struct ksnp_message_context **context) NOEXCEPT;

/**
 * @brief Destroy a previously created message context.
 *
 * @param context The message context to destroy, which must have been
 * previously created using @ref ksnp_message_context_create().
 */
void ksnp_message_context_destroy(struct ksnp_message_context *context) NOEXCEPT;

/**
 * @brief Check if more data needs to be added before a message can be read.
 *
 * Calling @ref ksnp_message_context_read_data() only if this function returns
 * true ensures the least amount of data needs to be buffered.
 *
 * @param ctx The message context used to deserialize the message data.
 * @return true if no message is currently available for reading.
 * @return false if some message data is available for reading.
 */
bool ksnp_message_context_want_read(struct ksnp_message_context *ctx) NOEXCEPT;

/**
 * @brief Read data from a buffer and check for additional messages.
 *
 * This function can be used to provide the message context with further data
 * received. The context buffers this data until it is ready to be deserialized
 * into a message. To prevent this buffer from growing unduly (or filling up
 * entirely), the @ref ksnp_message_context_want_read() function should be used
 * to determine when it is appropriate to add more data.
 *
 * After calling this function, @ref ksnp_message_context_next_message() should
 * be called as soon as possible, or when @ref ksnp_message_context_want_read()
 * returns false.
 *
 * To indicate the receiving channel from the server has been closed, i.e., EOF
 * was reached, the @p len parameter can be set to the value 0.
 *
 * @param ctx The message context used to deserialize the message data.
 * @param data [optional] Pointer to a buffer containing more data. This can be
 * NULL @e only when @p len is 0.
 * @param len [in,out] Pointer to the length value, which must match the length
 * of the input buffer @p data, or be set to 0. When 0, the @p data parameter
 * may be NULL. If this function returns successfully, the number of bytes
 * actually read are written to the length value, which may be 0.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure. On error, no
 * data will be added to the context.
 */
NODISCARD ksnp_error ksnp_message_context_read_data(struct ksnp_message_context *ctx,
                                                    unsigned char const         *data,
                                                    size_t                      *len) NOEXCEPT;

/**
 * @brief Check if the context has data available to write.
 *
 * This function can be used to determine of the context has any data available
 * to write, which can be read using @ref ksnp_message_context_write_data().
 * Data normally becomes available after a call to @ref
 * ksnp_message_context_write_message().
 *
 * @param ctx The message context used.
 * @return true if data is available for writing, and @ref
 * ksnp_message_context_write_data() should be called as soon as possible.
 * @return false if no data is available to be written.
 */
bool ksnp_message_context_want_write(struct ksnp_message_context *ctx) NOEXCEPT;

/**
 * @brief Write pending message data to a buffer.
 *
 * This function can be used to retrieve data to write. This is normally called
 * when calling @ref ksnp_message_context_want_write() returns true. The message
 * context buffers this data until it is extracted. To prevent this buffer from
 * growing unduly (or filling up entirely), the @ref
 * ksnp_message_context_want_write() function should be used to determine when
 * it is appropriate to send further data.
 *
 * @param ctx The message context used to serialize message data.
 * @param data [out] Pointer to a buffer to write data to.
 * @param len [in,out] Pointer to the length value, which must match the length
 * of the output buffer. If this function returns successfully, the number of
 * bytes actually written are written to the length value, which may be 0.
 * @return @ref KSNP_E_NO_ERROR on success.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_message_context_write_data(struct ksnp_message_context *ctx,
                                                     unsigned char               *data,
                                                     size_t                      *len) NOEXCEPT;

/**
 * @brief Retrieve the next message from the context if any exists.
 *
 * When a previous call to @ref ksnp_message_context_want_read() returned false,
 * or after calling
 * @ref ksnp_message_context_read_data(), this function may be used to decode
 * and retrieve the next message.
 *
 * The resulting message data is valid only until the next call to
 * @ref ksnp_message_context_next_message(), a call to @ref
 * ksnp_message_context_read_data(), or a call to
 * @ref ksnp_message_context_destroy().
 *
 * @param ctx The message context containing the message data.
 * @param msg [out] Pointer where the address of the last decoded message is
 * written to. This message is valid until another operation modifies the
 * context. This pointer is set to the last message received, or NULL if no
 * message is available. The output of this parameter is only valid if the
 * return value is @ref KSNP_E_NO_ERROR.
 * @param protocol_error [out] Pointer where the specific cause of a protocol
 * violation is written to. The output of this parameter is only valid if the
 * return value is @ref KSNP_E_PROTOCOL_ERROR.
 * @return @ref KSNP_E_NO_ERROR on success (though @p msg may still be set to
 * NULL).
 * @return @ref KSNP_E_PROTOCOL_ERROR if a protocol error occurs; the @p
 * protocol_error parameter is then valid.
 * @return Any of the values from the @ref ksnp_error enum on failure.
 */
NODISCARD ksnp_error ksnp_message_context_next_message(struct ksnp_message_context *ctx,
                                                       struct ksnp_message const  **msg,
                                                       struct ksnp_protocol_error  *protocol_error) NOEXCEPT;

/**
 * @brief Prepare a message for writing to a buffer.
 *
 * Inserts a message into the context for later serialization using
 * @ref ksnp_message_context_write_data(). To avoid the internal write buffer
 * from growing unduly, or filling up entirely, check that @ref
 * ksnp_message_context_want_write() returns false before calling this function.
 *
 * @param ctx The message context used to serialize the message.
 * @param msg Pointer to a message to serialize.
 * @return @ref KSNP_E_NO_ERROR on success (though @p msg may still be set to
 * NULL).
 * @return Any of the values from the @ref ksnp_error enum on failure. On error, no
 * message data will be added to the context.
 */
NODISCARD ksnp_error ksnp_message_context_write_message(struct ksnp_message_context *ctx,
                                                        struct ksnp_message const   *msg) NOEXCEPT;

// NOLINTEND(modernize-use-trailing-return-type)

#include "ksnp/compat.h"
