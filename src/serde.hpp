#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "helpers.hpp"
#include "ksnp/messages.h"
#include "ksnp/serde.h"

namespace ksnp
{

/**
 * @brief Wrapper for ksnp_buffer that makes it act as a Container.
 */
struct buffer {
private:
    ksnp_buffer *buf;

public:
    /** Buffer element type. */
    using element_type    = unsigned char;
    /** Buffer size type. */
    using size_type       = size_t;
    /** Buffer pointer difference type. */
    using difference_type = std::ptrdiff_t;

    /**
     * @brief Construct a new buffer object using the given buffer as actual
     * storage.
     *
     * @param buf Buffer to use. The buffer must outlive this object.
     */
    explicit buffer(ksnp_buffer *buf) : buf(buf)
    {}

    /**
     * @brief Return a pointer to the data in the buffer.
     *
     * @return Pointer to the buffer's data, which may be null.
     */
    [[nodiscard]] auto data() const noexcept -> unsigned char const *
    {
        return this->buf->data(this->buf);
    }

    /**
     * @brief Return a pointer to the data in the buffer.
     *
     * @return Pointer to the buffer's data, which may be null.
     */
    [[nodiscard]] auto data() noexcept -> unsigned char *
    {
        return this->buf->data(this->buf);
    }

    /**
     * @brief Return the number of elements in the buffer.
     *
     * @return The number of elements stored in the buffer.
     */
    [[nodiscard]] auto size() const noexcept -> size_type
    {
        return this->buf->size(this->buf);
    }

    /**
     * @brief Check if the buffer is empty.
     *
     * @return true if the buffer is empty.
     * @return false otherwise.
     */
    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return this->size() == 0;
    }

    /**
     * @brief Consume data from the front of the buffer.
     *
     * @param count Number of elements to consume, must be within the size of
     * the buffer. Remaining data is moved to the front of the buffer.
     */
    void consume(size_t count) noexcept
    {
        this->buf->consume(this->buf, count);
    }

    /**
     * @brief Append the data to the buffer.
     *
     * The buffer must accept all the data, or an exception is thrown.
     *
     * @param data Pointer to the data to append.
     * @param len Size of the data to append.
     */
    void append_exact(unsigned char const *data, size_t len)
    {
        auto written = len;
        if (auto err = this->buf->append(this->buf, data, &written); err != ksnp_error::KSNP_E_NO_ERROR) {
            throw exception(err);
        }
        if (len != written) {
            throw exception(ksnp_error::KSNP_E_INSUFFICIENT_BUFFER);
        }
    }

    /**
     * @brief Append the data to the buffer.
     *
     * @param data Pointer to the data to append.
     * @param len [in,out] Pointer to the size of the data to append. When this
     * function returns, the amount of data appended is written here.
     */
    void append(unsigned char const *data, size_t *len)
    {
        if (auto err = this->buf->append(this->buf, data, len); err != ksnp_error::KSNP_E_NO_ERROR) {
            throw exception(err);
        }
    }

    /**
     * @brief Truncate the buffer to the given size.
     *
     * @param size Size to truncate the buffer to. Must be within the current
     * size of the buffer.
     */
    void truncate(size_t size) noexcept
    {
        this->buf->truncate(this->buf, size);
    }

#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    /**
     * @brief Start iterator for the buffer.
     *
     * @return Start iterator for the buffer.
     */
    [[nodiscard]] auto begin() -> unsigned char *
    {
        return this->data();
    }

    /**
     * @brief End iterator for the buffer.
     *
     * @return End iterator for the buffer.
     */
    [[nodiscard]] auto end() -> unsigned char *
    {
        return this->data() + this->size();
    }

    /**
     * @brief Start iterator for the buffer.
     *
     * @return Start iterator for the buffer.
     */
    [[nodiscard]] auto begin() const -> unsigned char const *
    {
        return this->data();
    }

    /**
     * @brief End iterator for the buffer.
     *
     * @return End iterator for the buffer.
     */
    [[nodiscard]] auto end() const -> unsigned char const *
    {
        return this->data() + this->size();
    }
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
};

/**
 * @brief Buffer using std::vector as a basis.
 */
class vector_buffer
    : protected ksnp_buffer
    , public std::vector<unsigned char>
{
public:
    /**
     * @brief Construct a new vector buffer object.
     */
    vector_buffer()
        : ksnp_buffer{
              .data      = data_fn,
              .size      = size_fn,
              .consume   = consume_fn,
              .append    = append_fn,
              .truncate  = truncate_fn,
              .user_data = this,
          }
    {}

    /** @brief Copy constructor. */
    vector_buffer(vector_buffer const &)     = default;
    /** @brief Move constructor. */
    vector_buffer(vector_buffer &&) noexcept = default;

    ~vector_buffer() = default;

    /** @brief Copy assignment operator. */
    auto operator=(vector_buffer const &) -> vector_buffer &     = default;
    /** @brief Move assignment operator. */
    auto operator=(vector_buffer &&) noexcept -> vector_buffer & = default;

    using vector::data;
    using vector::size;

    /**
     * @brief Get a vector_buffer pointer from a C API ksnp_buffer pointer.
     *
     * @param base_buffer C API buffer pointer. Must have been created using
     * @ref as_buffer_ptr().
     * @return Pointer to a vector_buffer.
     */
    static auto from_buffer_ptr(ksnp_buffer const *base_buffer) -> vector_buffer const *
    {
        return static_cast<vector_buffer const *>(base_buffer->user_data);
    }

    /**
     * @brief Get a vector_buffer pointer from a C API ksnp_buffer pointer.
     *
     * @param base_buffer C API buffer pointer. Must have been created using
     * @ref as_buffer_ptr().
     * @return Pointer to a vector_buffer.
     */
    static auto from_buffer_ptr(ksnp_buffer *base_buffer) -> vector_buffer *
    {
        return static_cast<vector_buffer *>(base_buffer->user_data);
    }

    /**
     * @brief Return a C API ksnp_buffer pointer that can be used with the C
     * API.
     *
     * @return A ksnp_buffer pointer that allows this instance to be used with
     * the C API. The pointer is valid for as long as this object is not
     * modified.
     */
    auto as_buffer_ptr() -> ksnp_buffer *
    {
        return this;
    }

private:
    static auto data_fn(struct ksnp_buffer *buffer) noexcept -> unsigned char *

    {
        return static_cast<vector_buffer *>(buffer)->data();
    }

    static auto size_fn(struct ksnp_buffer *buffer) noexcept -> size_t
    {
        return static_cast<vector_buffer *>(buffer)->size();
    }

    static void consume_fn(struct ksnp_buffer *buffer, size_t count) noexcept
    {
        auto *self = static_cast<vector_buffer *>(buffer);
        self->erase(self->begin(), self->begin() + static_cast<std::vector<unsigned char>::difference_type>(count));
    }

    static auto append_fn(struct ksnp_buffer  *buffer,
                          unsigned char const *data,
                          size_t              *len) noexcept  // NOLINT(readability-non-const-parameter)
        -> ksnp_error
    try {
        auto *self = static_cast<vector_buffer *>(buffer);
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        self->insert(self->end(), data, data + *len);
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
        return ksnp_error::KSNP_E_NO_ERROR;
    } catch (std::bad_alloc const &) {
        return ksnp_error::KSNP_E_NO_MEM;
    }

    static void truncate_fn(struct ksnp_buffer *buffer, size_t size) noexcept
    {
        static_cast<vector_buffer *>(buffer)->resize(size);
    }
};

/** @brief Type alias for JSON objects with automatic lifetime duration. */
using json_ptr = unique_obj<json_object *, json_object_put>;

/**
 * @brief Wrapper for JSON objects of type object.
 *
 * Unlike json_ptr, this type ensures that the contained JSON object, if any,
 * is an object.
 */
class json_obj : json_ptr
{

public:
    /** Constructor. */
    json_obj() = default;

    /**
     * @brief Wrap an existing JSON object and increase its reference count.
     *
     * Takes ownership of the object by increasing its reference count. This is
     * intended to wrap non-owned pointers, such as pointers obtained from
     * json_object_iterator_peek_value().
     *
     * @param obj The object to wrap.
     */
    explicit json_obj(json_object *obj) : json_obj(obj, false)
    {}

    /**
     * @brief Wrap an existing JSON object.
     *
     * May take ownership of the object if stolen, or share it.
     *
     * @param obj The object to wrap.
     * @param steal Indicate if ownership should be taken or shared. If false,
     * ownership is shared and the reference count of obj is increased.
     * Otherwise, the reference count is left unmodified.
     */
    explicit json_obj(json_object *obj, bool steal) : json_ptr(ensure_object(obj))
    {
        if (!steal) {
            json_object_get(this->get());
        }
    }

    using json_ptr::operator*;
    using json_ptr::operator->;
    using json_ptr::operator bool;

private:
    static auto ensure_object(json_object *obj) -> json_object *
    {
        if (json_object_is_type(obj, json_type_object) == 0) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE, "expected JSON object");
        }
        return obj;
    }
};

/**
 * @brief Wrapper for stream addresses that manages the lifetime of the address
 * strings.
 */
class stream_address
{
private:
    json_ptr     sae;
    json_ptr     network;
    ksnp_address address;

public:
    /** Constructor. */
    stream_address() : address{.sae = nullptr, .network = nullptr}
    {}

    /**
     * @brief Construct a new stream address from two optional JSON strings.
     *
     * @param sae JSON object containing the SAE string. May also be null.
     * @param network JSON object containing the network string. May also be
     * null.
     */
    stream_address(json_ptr sae, json_ptr network)
        : sae(std::move(sae))
        , network(std::move(network))
        , address{.sae = json_object_get_string(*this->sae), .network = json_object_get_string(*this->network)}
    {}

    /**
     * @brief Get the C API address.
     *
     * @return The address, using this object to store the strings. The result
     * may not outlive this instance.
     */
    [[nodiscard]] auto get_address() const -> ksnp_address const &
    {
        return this->address;
    }
};

/**
 * @brief Storage object for the payload of stream_open messages.
 */
class stream_open_params
{
private:
    ksnp_stream_open_params params;
    stream_address          source;
    stream_address          destination;
    json_obj                extensions;
    json_obj                required_extensions;

public:
    /**
     * @brief Construct a new stream open params object.
     *
     * @param params Stream parameters to wrap.
     * @param source JSON object wrapping the source parameter.
     * @param destination JSON object wrapping the destination parameter.
     * @param extensions JSON object wrapping the extensions parameter.
     * @param required_extensions JSON object wrapping the required_extensions
     * parameter.
     */
    stream_open_params(ksnp_stream_open_params params,
                       stream_address          source,
                       stream_address          destination,
                       json_obj                extensions,
                       json_obj                required_extensions)
        : params(params)
        , source(std::move(source))
        , destination(std::move(destination))
        , extensions(std::move(extensions))
        , required_extensions(std::move(required_extensions))
    {}

    /**
     * @brief Return a C API ksnp_stream_open_params pointer that can be used
     * with the C API.
     *
     * @return A ksnp_stream_open_params pointer that allows this instance to be
     * used with the C API. The pointer is valid for as long as this object is
     * not modified.
     */
    [[nodiscard]] auto get_params() -> ksnp_stream_open_params *
    {
        return &this->params;
    }
};

/**
 * @brief Storage object for the accepted payload of stream_open_reply messages.
 */
class stream_accepted_params
{
private:
    ksnp_stream_accepted_params params;
    json_obj                    extensions;

public:
    /**
     * @brief Construct a new stream accepted params object.
     *
     * @param params Stream parameters to wrap.
     * @param extensions JSON object wrapping the extensions parameter.
     */
    stream_accepted_params(ksnp_stream_accepted_params params, json_obj extensions)
        : params(params)
        , extensions(std::move(extensions))
    {}

    /**
     * @brief Return a C API ksnp_stream_accepted_params pointer that can be
     * used with the C API.
     *
     * @return A ksnp_stream_accepted_params pointer that allows this instance
     * to be used with the C API. The pointer is valid for as long as this
     * object is not modified.
     */
    [[nodiscard]] auto get_params() -> ksnp_stream_accepted_params *
    {
        return &this->params;
    }
};

/**
 * @brief Storage object for the QoS payload of stream_open_reply messages.
 */
class stream_qos_params
{
private:
    ksnp_stream_qos_params params;
    std::vector<uint16_t>  chunk_list;
    std::vector<ksnp_rate> min_bps_list;
    std::vector<uint32_t>  ttl_list;
    std::vector<uint32_t>  provision_size_list;
    json_obj               extensions;

public:
    /**
     * @brief Construct a new stream qos params object
     *
     * @param params Stream parameters to wrap.
     * @param chunk_list Storage for the chunk_size value if a list.
     * @param min_bps_list Storage for the min_bps value if a list.
     * @param ttl_list Storage for the ttl value if a list.
     * @param provision_size_list Storage for the provision_size value if a
     * list.
     * @param extensions JSON object wrapping the extensions parameter.
     */
    stream_qos_params(ksnp_stream_qos_params params,
                      std::vector<uint16_t>  chunk_list,
                      std::vector<ksnp_rate> min_bps_list,
                      std::vector<uint32_t>  ttl_list,
                      std::vector<uint32_t>  provision_size_list,
                      json_obj               extensions)
        : params(params)
        , chunk_list(std::move(chunk_list))
        , min_bps_list(std::move(min_bps_list))
        , ttl_list(std::move(ttl_list))
        , provision_size_list(std::move(provision_size_list))
        , extensions(std::move(extensions))
    {}

    /**
     * @brief Return a C API ksnp_stream_qos_params pointer that can be used
     * with the C API.
     *
     * @return A ksnp_stream_qos_params pointer that allows this instance to be
     * used with the C API. The pointer is valid for as long as this object is
     * not modified.
     */
    [[nodiscard]] auto get_params() -> ksnp_stream_qos_params *
    {
        return &this->params;
    }
};

/**
 * @brief Storage object for the parameter payload of key_data messages.
 */
class key_data_parameters
{
private:
    json_obj parameters;

public:
    /**
     * @brief Construct a new key data parameters object
     *
     * @param parameters JSON object wrapping the key data parameters.
     */
    explicit key_data_parameters(json_obj parameters) : parameters(std::move(parameters))
    {}

    /**
     * @brief Return a json_object pointer for use with a key_data message.
     *
     * @return A json_object pointer that allows this instance to be used with
     * the C API. The pointer is valid for as long as this object is not
     * modified.
     */
    [[nodiscard]] auto get_parameters() -> json_object *
    {
        return *this->parameters;
    }
};

template<std::unsigned_integral SourceUint, typename U8 = unsigned char>
[[nodiscard]] constexpr auto uint_to_be(SourceUint val) -> std::array<U8, sizeof(SourceUint)>
{
    constexpr std::size_t COUNT = sizeof(SourceUint);
    constexpr int         BITS  = std::numeric_limits<U8>::digits;

    std::array<U8, COUNT> result{};

    for (size_t i = 0; i < result.size(); i++) {
        result[i] = static_cast<U8>(val >> (BITS * (COUNT - i - 1)));
    }

    return result;
}

/**
 * @brief All possible messages sent between a client and server.
 */
class message
    : public std::variant<ksnp_msg_version,
                          ksnp_msg_open_stream,
                          ksnp_msg_open_stream_reply,
                          ksnp_msg_close_stream,
                          ksnp_msg_close_stream_notify,
                          ksnp_msg_close_stream_reply,
                          ksnp_msg_suspend_stream,
                          ksnp_msg_suspend_stream_notify,
                          ksnp_msg_suspend_stream_reply,
                          ksnp_msg_capacity_notify,
                          ksnp_msg_key_data_notify,
                          ksnp_msg_keep_alive_stream,
                          ksnp_msg_keep_alive_stream_reply,
                          ksnp_msg_error>
{
private:
    using base = std::variant<ksnp_msg_version,
                              ksnp_msg_open_stream,
                              ksnp_msg_open_stream_reply,
                              ksnp_msg_close_stream,
                              ksnp_msg_close_stream_notify,
                              ksnp_msg_close_stream_reply,
                              ksnp_msg_suspend_stream,
                              ksnp_msg_suspend_stream_notify,
                              ksnp_msg_suspend_stream_reply,
                              ksnp_msg_capacity_notify,
                              ksnp_msg_key_data_notify,
                              ksnp_msg_keep_alive_stream,
                              ksnp_msg_keep_alive_stream_reply,
                              ksnp_msg_error>;

public:
    using base::base;
    using base::operator=;

    /**
     * @brief Convert a C API message into this message type.
     */
    static auto from_message(ksnp_message msg) -> std::optional<message>;

    /**
     * @brief Convert this message into a C API message.
     *
     * @return A C API message. The lifetime of the message may not exceed that
     * of this object.
     */
    [[nodiscard]] auto into_message() const noexcept -> ksnp_message;
};

/**
 * @brief A type for serializing and deserializing protocol messages.
 *
 * A message context is used to buffer incoming data and outgoing data
 * and translate it to and from protocol messages.
 *
 * To use a message context, data must be read and written using @ref
 * read_data() and @ref write_data(). If external buffers are provided, data may
 * be directly read from and written to those.
 *
 * After reading data, @ref next_message() should be called as soon as possible
 * to process the message data and free up the input buffer.
 *
 * To check if the message context requires more data to read, or has data to
 * write, the @ref want_read() and @ref want_write() functions can be used. If
 * either of these returns true, the @ref read_data() and
 * @ref write_data() functions should be called as appropriate.
 *
 * It is recommended to use this type in tandem with either @ref ksnp_server or
 * @ref ksnp_client, as these types handle the protocol state machines.
 *
 * This type cannot be used concurrently across threads, but can be shared
 * between threads.
 */
class message_context
{
private:
    using message_payload = std::
        variant<std::monostate, stream_open_params, stream_accepted_params, stream_qos_params, key_data_parameters>;

    enum class json_ser_flag : std::uint8_t {
        plain,
        with_length,
    };

    // Storage used when no user-provided buffers are used.
    std::optional<vector_buffer> input_storage;
    std::optional<vector_buffer> output_storage;

    buffer input_data;
    buffer output_data;

    std::optional<std::uint16_t> last_message_len;
    std::string                  status_message;
    message_payload              last_message_payload;
    bool                         eof;

    void free_last_message();

    auto load_next_string(std::span<std::uint8_t const> &data) -> char const *;

    auto load_next_json(std::span<std::uint8_t const> &data, std::size_t json_len) -> json_obj;

    template<std::unsigned_integral T>
    void write_uint(T val)
    {
        auto bytes = uint_to_be(val);
        this->output_data.append_exact(bytes.data(), bytes.size());
    }

    void write_u16(std::uint16_t val)
    {
        write_uint(val);
    }

    void write_u32(std::uint32_t val)
    {
        write_uint(val);
    }

    template<typename T>
    void write_enum(T val)
    {
        write_uint(static_cast<typename std::underlying_type_t<T>>(val));
    }

    void write_json(json_object *obj, json_ser_flag flag);

    void write_message(char const *msg);

    void write_parameters(ksnp_stream_open_params const *params);

    void write_reply_parameters(ksnp_stream_accepted_params const *params);

    void write_qos_parameters(ksnp_stream_qos_params const *params);

public:
    /**
     * @brief Create a new message context that can be used to serialize and
     * deserialize messages.
     *
     * This message context uses its own buffers to store data to read and write
     * (as handled via @ref read_data() and @ref write_data()). These buffers
     * can grow indefinitely; to avoid unbounded growth use @ref want_read() and
     * @ref want_write().
     */
    message_context()
        : input_storage(vector_buffer())
        , output_storage(vector_buffer())
        , input_data(this->input_storage->as_buffer_ptr())
        , output_data(this->output_storage->as_buffer_ptr())
        , eof(false)
    {}

    /**
     * @brief Create a new message context that can be used to serialize and
     * deserialize messages using custom buffers.
     *
     * The message context will read and write data using the provided buffer
     * objects. The caller may modify these buffers either directly, or using
     * read_data() or write_data().
     *
     * The provided buffers must be able to hold at least one message, see the
     * @a KSNP_MAX_MSG_LEN constant.
     *
     * @param read_buffer Pointer to a buffer object that is used for reading data.
     * Note that data returned by the created message context may refer to data in
     * the read buffer. Premature modification of that buffer may invalidate this
     * data. The pointer must remain valid for the lifetime of the message context.
     * @param write_buffer Pointer to a buffer object that is used for writing
     * data. The pointer must remain valid for the lifetime of the message
     * context.
     */
    message_context(ksnp_buffer *read_buffer,  // NOLINT: bugprone-easily-swappable-parameters
                    ksnp_buffer *write_buffer)
        : input_data(read_buffer)
        , output_data(write_buffer)
        , eof(false)
    {}

    /**
     * @brief Check if more data needs to be added before a message can be read.
     *
     * Calling @ref read_data() only if this function returns true ensures the
     * least amount of data needs to be buffered.
     *
     * If this function returns false, either a message is pending which can be
     * extracted with @ref next_message(), or EOF was reached after previously
     * calling @ref read_data() with an empty buffer.
     *
     * @return true if no message is currently available for reading.
     * @return false if some message data is available for reading, or EOF was
     * reached.
     */
    [[nodiscard]] auto want_read() const noexcept -> bool;

    /**
     * @brief Read data from a buffer and check for additional messages.
     *
     * This function can be used to provide the message context with further
     * data. The context buffers this data until it is ready to be deserialized
     * into a message. To prevent this buffer from growing unduly (or filling up
     * entirely), the @ref want_read() function should be used to determine when
     * it is appropriate to add more data.
     *
     * After calling this function, @ref next_message() should be called as soon
     * as possible.
     *
     * To indicate the receiving channel has been closed, i.e., EOF was reached,
     * an empty buffer can be provided.
     *
     * @param data Buffer containing the data to read. An empty buffer indicates
     * EOF.
     * @return The number of bytes actually read, which may be less than the
     * input if the associated buffer does not have sufficient capacity.
     */
    auto read_data(std::span<unsigned char const> data) -> size_t;

    /**
     * @brief Check if the context has data available to write.
     *
     * This function can be used to determine if the context has any data
     * available to write, which can be retrieved using @ref write_data(). Data
     * normally becomes available after a call to @ref write_message(message
     * const &)/@ref write_message(ksnp_message const *).
     *
     * @return true if data is available for writing, and @ref write_data()
     * should be called as soon as possible.
     * @return false if no data is available to be written.
     */
    [[nodiscard]] auto want_write() const noexcept -> bool;

    /**
     * @brief Write pending message data to a buffer.
     *
     * This function can be used to retrieve data to write. This is normally
     * called when calling @ref want_write() returns true. The message context
     * buffers this data until it is extracted. To prevent this buffer from
     * growing unduly (or filling up entirely), the @ref want_write() function
     * should be used to determine when it is appropriate to send further data.
     *
     * @param data [out] Buffer to write data to.
     * @return The number of bytes actually written.
     */
    auto write_data(std::span<unsigned char> data) -> size_t;

    /**
     * @brief Retrieve the next message from the context if any exists.
     *
     * When a previous call to @ref want_read() returned false, or after calling
     * @ref read_data(), this function may be used to decode and retrieve the
     * next message.
     *
     * The resulting message data is valid only until the next call to
     * @ref next_message(), a call to @ref read_data(), this object is destroyed
     * or the underlying buffer is modified.
     *
     * @return The last decoded message, if any. This message is valid until
     * another operation modifies the context.
     */
    auto next_message() -> std::optional<message>;

    /**
     * @brief Prepare a message for writing to a buffer.
     *
     * Inserts a message into the context for later serialization using
     * @ref write_data(). To avoid the internal write buffer from growing
     * unduly, or filling up entirely, check that @ref want_write() returns
     * false before calling this function.
     *
     * @param message Pointer to a message to serialize.
     */
    void write_message(struct ksnp_message const *message);

    /**
     * @brief Prepare a message for writing to a buffer.
     *
     * Inserts a message into the context for later serialization using
     * @ref write_data(). To avoid the internal write buffer from growing
     * unduly, or filling up entirely, check that @ref want_write() returns
     * false before calling this function.
     *
     * @param message Message to serialize.
     */
    void write_message(message const &message)
    {
        auto raw_message = message.into_message();
        this->write_message(&raw_message);
    }

private:
    auto parse_message(std::uint16_t type, std::span<unsigned char const> data) -> message;
};

}  // namespace ksnp
