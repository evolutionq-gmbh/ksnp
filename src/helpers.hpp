#pragma once

#include <algorithm>
#include <concepts>
#include <exception>
#include <new>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

#include <json-c/json_object.h>

#include "ksnp/client.h"
#include "ksnp/messages.h"
#include "ksnp/serde.h"
#include "ksnp/server.h"
#include "ksnp/types.h"

namespace ksnp
{

template<std::copyable Code>
class base_exception : public std::exception
{
    Code        error_code;
    char const *desc;

public:
    explicit base_exception(Code error_code) : error_code(error_code), desc(nullptr)
    {}

    base_exception(Code error_code, char const *desc) : error_code(error_code), desc(desc)
    {}

    base_exception(base_exception const &)                     = default;
    base_exception(base_exception &&)                          = default;
    auto operator=(base_exception const &) -> base_exception & = default;
    auto operator=(base_exception &&) -> base_exception &      = default;

    ~base_exception() override = default;

    [[nodiscard]] auto code() const noexcept -> Code
    {
        return this->error_code;
    }

    [[nodiscard]] auto description() const noexcept -> char const *
    {
        return this->desc;
    }

    [[nodiscard]] auto what() const noexcept -> char const * override
    {
        return this->desc != nullptr ? this->desc : "";
    }
};

class exception : public base_exception<ksnp_error>
{
public:
    using base_exception::base_exception;

    exception(exception const &)                     = default;
    exception(exception &&)                          = default;
    auto operator=(exception const &) -> exception & = default;
    auto operator=(exception &&) -> exception &      = default;

    ~exception() override;
};

class protocol_exception : public base_exception<ksnp_error_code>
{
public:
    using base_exception::base_exception;

    explicit protocol_exception(ksnp_protocol_error protocol_error)
        : base_exception(protocol_error.code, protocol_error.description)
    {}

    protocol_exception(protocol_exception const &)                     = default;
    protocol_exception(protocol_exception &&)                          = default;
    auto operator=(protocol_exception const &) -> protocol_exception & = default;
    auto operator=(protocol_exception &&) -> protocol_exception &      = default;

    ~protocol_exception() override;

    [[nodiscard]] auto what() const noexcept -> char const * override
    {
        return this->description() != nullptr ? this->description() : ksnp_protocol_error_description(this->code());
    }
};

class version_exception : public std::exception
{
public:
    using std::exception::exception;

    version_exception(version_exception const &)                     = default;
    version_exception(version_exception &&)                          = default;
    auto operator=(version_exception const &) -> version_exception & = default;
    auto operator=(version_exception &&) -> version_exception &      = default;

    ~version_exception() override;
};

/**
 * @brief RAII wrapper for objects that use an explicit delete/close function.
 *
 * This wrapper provides an interface similar to that of std::unique_ptr, but
 * geared towards wrapping any object that uses some (static) release function.
 *
 * @tparam T Type of the wrapped object, often a pointer.
 * @tparam delete_fn Function to call to release resources of type T.
 * @tparam zero_val The zero or 'unset' value. Often `nullptr`.
 */
template<typename T, auto delete_fn, T zero_val = T{}>
requires(std::copyable<T> && std::equality_comparable<T> && std::invocable<decltype(delete_fn), T>)
class unique_obj
{
private:
    T object;

public:
    using element_type = T;

    /**
     * @brief Construct an empty wrapper.
     */
    unique_obj() noexcept : object(zero_val)
    {}

    /**
     * @brief Construct a wrapper from an existing object value.
     *
     * @param object to initialize the wrapper with, may be zero_val.
     */
    explicit unique_obj(T object) noexcept : object(object)
    {}

    explicit unique_obj(unique_obj const &) = delete;
    unique_obj(unique_obj &&other) noexcept : object(other.object)
    {
        other.object = zero_val;
    }

    auto operator=(unique_obj const &) -> unique_obj & = delete;
    auto operator=(unique_obj &&other) noexcept -> unique_obj &
    {
        using std::swap;
        swap(this->object, other.object);
        return *this;
    }
    auto operator=(T other_object) noexcept -> unique_obj &
    {
        this->reset(other_object);
        return *this;
    }

    ~unique_obj()
    {
        if (this->object != zero_val) {
            delete_fn(this->object);
        }
    }

    /**
     * @brief Return a copy of the wrapped object value.
     *
     * @return A copy of the wrapped object value. May be zero_val.
     */
    [[nodiscard]] auto get() const noexcept -> T
    {
        return this->object;
    }

    /**
     * @brief Return the wrapped object value.
     *
     * @return The wrapped object value. May be zero_val.
     */
    [[nodiscard]] auto get() noexcept -> T &
    {
        return this->object;
    }

    /**
     * @brief Dereference into the object value.
     *
     * @return A copy of the wrapped object value. May be zero_val.
     */
    [[nodiscard]] auto operator*() const noexcept -> T
    {
        return this->object;
    }

    /**
     * @brief Dereference into the object value.
     *
     * @return A copy of the wrapped object value. May be zero_val.
     */
    [[nodiscard]] auto operator->() const noexcept -> T
    {
        return this->object;
    }

    /**
     * @brief Cast into the wrapped object value.
     *
     * @return A copy of the wrapped object value. May be zero_val.
     */
    [[nodiscard]] explicit operator T() const noexcept
    {
        return this->object;
    }

    /**
     * @brief Test if an object is held.
     *
     * @return true If a value is contained.
     * @return false If no value is contained (compares equal to zero_val).
     */
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return this->object != zero_val;
    }

    /**
     * @brief Replace the contained object with the given value.
     *
     * The contained value, if any, is released.
     *
     * @param new_object Object to replace with, defaults to zero_val.
     */
    void reset(T new_object = zero_val)
    {
        if (this->object != zero_val) {
            delete_fn(this->object);
        }
        this->object = new_object;
    }

    /**
     * @brief Extracts the contained object value.
     *
     * @return The contained object value. The object is released from this
     * wrapper.
     */
    [[nodiscard]] auto release() -> T
    {
        T res        = this->object;
        this->object = zero_val;
        return res;
    }
};

/// @brief Buffer using std::vector as a basis.
class vector_buffer
    : protected ksnp_buffer
    , public std::vector<unsigned char>
{
public:
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

    vector_buffer(vector_buffer const &)     = default;
    vector_buffer(vector_buffer &&) noexcept = default;

    ~vector_buffer() = default;

    auto operator=(vector_buffer const &) -> vector_buffer &     = default;
    auto operator=(vector_buffer &&) noexcept -> vector_buffer & = default;

    using vector::data;
    using vector::size;

    static auto from_buffer_ptr(ksnp_buffer const *base_buffer) -> vector_buffer const *
    {
        return static_cast<vector_buffer const *>(base_buffer->user_data);
    }

    static auto from_buffer_ptr(ksnp_buffer *base_buffer) -> vector_buffer *
    {
        return static_cast<vector_buffer *>(base_buffer->user_data);
    }

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

class zstring_view : public std::string_view
{
public:
    explicit constexpr zstring_view(std::string_view str) : std::string_view(str)
    {}

    [[nodiscard]] auto c_str() const noexcept -> char const *
    {
        return this->data();
    }
};

constexpr auto operator""_zsv(char const *str, size_t len) noexcept -> zstring_view
{
    return zstring_view{
        std::string_view{str, len}
    };
}

class server_event
    : public std::variant<ksnp_server_event_handshake,
                          ksnp_server_event_open_stream,
                          ksnp_server_event_close_stream,
                          ksnp_server_event_suspend_stream,
                          ksnp_server_event_keep_alive,
                          ksnp_server_event_new_capacity,
                          ksnp_server_event_error>
{
public:
    using base = std::variant<ksnp_server_event_handshake,
                              ksnp_server_event_open_stream,
                              ksnp_server_event_close_stream,
                              ksnp_server_event_suspend_stream,
                              ksnp_server_event_keep_alive,
                              ksnp_server_event_new_capacity,
                              ksnp_server_event_error>;
    using base::base;
    using base::operator=;

    static auto from_event(ksnp_server_event event) -> std::optional<server_event>;

    [[nodiscard]] auto into_event() const noexcept -> ksnp_server_event;
};

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
public:
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
    using base::base;
    using base::operator=;

    static auto from_message(ksnp_message msg) -> std::optional<message>;

    [[nodiscard]] auto into_message() const noexcept -> ksnp_message;
};

// helper type for the visitor
template<class... Ts>
struct overloads : Ts... {
    using Ts::operator()...;
};

}  // namespace ksnp

#define CATCH_ALL                                      \
    catch (ksnp::exception & e)                        \
    {                                                  \
        return e.code();                               \
    }                                                  \
    catch (ksnp::protocol_exception &)                 \
    {                                                  \
        return ksnp_error::KSNP_E_PROTOCOL_ERROR;      \
    }                                                  \
    catch (version_exception &)                        \
    {                                                  \
        return ksnp_error::KSNP_E_UNSUPPORTED_VERSION; \
    }                                                  \
    catch (std::bad_alloc &)                           \
    {                                                  \
        return ksnp_error::KSNP_E_NO_MEM;              \
    }                                                  \
    catch (...)                                        \
    {                                                  \
        return ksnp_error::KSNP_E_UNKNOWN;             \
    }
