#pragma once

#include <algorithm>
#include <cassert>
#include <concepts>
#include <exception>
#include <json_object.h>
#include <netdb.h>
#include <optional>
#include <uuid/uuid.h>
#include <variant>

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

using message_t = std::variant<ksnp_msg_version,
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

using client_event = std::variant<ksnp_client_event_handshake,
                                  ksnp_client_event_stream_open,
                                  ksnp_client_event_stream_close,
                                  ksnp_client_event_stream_suspend,
                                  ksnp_client_event_key_data,
                                  ksnp_client_event_keep_alive,
                                  ksnp_client_event_error>;

using server_event = std::variant<ksnp_server_event_handshake,
                                  ksnp_server_event_open_stream,
                                  ksnp_server_event_close_stream,
                                  ksnp_server_event_suspend_stream,
                                  ksnp_server_event_keep_alive,
                                  ksnp_server_event_new_capacity,
                                  ksnp_server_event_error>;

// helper type for the visitor
template<class... Ts>
struct overloads : Ts... {
    using Ts::operator()...;
};

auto inline into_message(message_t msg) noexcept -> ::ksnp_message
{
    auto const visitor = overloads{
        [](ksnp_msg_version msg) -> ksnp_message {
            return ksnp_message{
                .type    = ksnp_message_type::KSNP_MSG_VERSION,
                .version = msg,
            };
        },
        [](ksnp_msg_open_stream msg) -> ksnp_message {
            return ksnp_message{
                .type        = ksnp_message_type::KSNP_MSG_OPEN_STREAM,
                .open_stream = msg,
            };
        },
        [](ksnp_msg_open_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type              = ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY,
                .open_stream_reply = msg,
            };
        },
        [](ksnp_msg_close_stream msg) -> ksnp_message {
            return ksnp_message{
                .type         = ksnp_message_type::KSNP_MSG_CLOSE_STREAM,
                .close_stream = msg,
            };
        },
        [](ksnp_msg_close_stream_notify msg) -> ksnp_message {
            return ksnp_message{
                .type                = ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY,
                .close_stream_notify = msg,
            };
        },
        [](ksnp_msg_close_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type               = ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY,
                .close_stream_reply = msg,
            };
        },
        [](ksnp_msg_suspend_stream msg) -> ksnp_message {
            return ksnp_message{
                .type           = ksnp_message_type::KSNP_MSG_SUSPEND_STREAM,
                .suspend_stream = msg,
            };
        },
        [](ksnp_msg_suspend_stream_notify msg) -> ksnp_message {
            return ksnp_message{
                .type                  = ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY,
                .suspend_stream_notify = msg,
            };
        },
        [](ksnp_msg_suspend_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type                 = ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY,
                .suspend_stream_reply = msg,
            };
        },
        [](ksnp_msg_capacity_notify msg) -> ksnp_message {
            return ksnp_message{
                .type            = ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY,
                .capacity_notify = msg,
            };
        },
        [](ksnp_msg_key_data_notify msg) -> ksnp_message {
            return ksnp_message{
                .type            = ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY,
                .key_data_notify = msg,
            };
        },
        [](ksnp_msg_keep_alive_stream msg) -> ksnp_message {
            return ksnp_message{
                .type              = ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM,
                .keep_alive_stream = msg,
            };
        },
        [](ksnp_msg_keep_alive_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type                    = ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY,
                .keep_alive_stream_reply = msg,
            };
        },
        [](ksnp_msg_error msg) -> ksnp_message {
            return ksnp_message{
                .type  = ksnp_message_type::KSNP_MSG_ERROR,
                .error = msg,
            };
        },
    };
    return std::visit(visitor, msg);
}

auto inline into_event(server_event event) noexcept -> ksnp_server_event
{
    auto const visitor = overloads{
        [](ksnp_server_event_handshake evt) -> ksnp_server_event {
            return ksnp_server_event{
                .type      = ksnp_server_event_type::KSNP_SERVER_EVENT_HANDSHAKE,
                .handshake = evt,
            };
        },
        [](ksnp_server_event_open_stream evt) -> ksnp_server_event {
            return ksnp_server_event{
                .type        = ksnp_server_event_type::KSNP_SERVER_EVENT_OPEN_STREAM,
                .open_stream = evt,
            };
        },
        [](ksnp_server_event_close_stream evt) -> ksnp_server_event {
            return ksnp_server_event{
                .type         = ksnp_server_event_type::KSNP_SERVER_EVENT_CLOSE_STREAM,
                .close_stream = evt,
            };
        },
        [](ksnp_server_event_suspend_stream evt) -> ksnp_server_event {
            return ksnp_server_event{
                .type           = ksnp_server_event_type::KSNP_SERVER_EVENT_SUSPEND_STREAM,
                .suspend_stream = evt,
            };
        },
        [](ksnp_server_event_keep_alive evt) -> ksnp_server_event {
            return ksnp_server_event{
                .type       = ksnp_server_event_type::KSNP_SERVER_EVENT_KEEP_ALIVE,
                .keep_alive = evt,
            };
        },
        [](ksnp_server_event_new_capacity evt) -> ksnp_server_event {
            return ksnp_server_event{
                .type         = ksnp_server_event_type::KSNP_SERVER_EVENT_NEW_CAPACITY,
                .new_capacity = evt,
            };
        },
        [](ksnp_server_event_error evt) -> ksnp_server_event {
            return ksnp_server_event{
                .type  = ksnp_server_event_type::KSNP_SERVER_EVENT_ERROR,
                .error = evt,
            };
        },
    };
    return std::visit(visitor, event);
}

auto inline into_event(client_event event) noexcept -> ksnp_client_event
{
    auto const visitor = overloads{
        [](ksnp_client_event_handshake evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type      = ksnp_client_event_type::KSNP_CLIENT_EVENT_HANDSHAKE,
                .handshake = evt,
            };
        },
        [](ksnp_client_event_stream_open evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type        = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_OPEN,
                .stream_open = evt,
            };
        },
        [](ksnp_client_event_stream_close evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type         = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_CLOSE,
                .stream_close = evt,
            };
        },
        [](ksnp_client_event_stream_suspend evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type           = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_SUSPEND,
                .stream_suspend = evt,
            };
        },
        [](ksnp_client_event_key_data evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type     = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_KEY_DATA,
                .key_data = evt,
            };
        },
        [](ksnp_client_event_keep_alive evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type       = ksnp_client_event_type::KSNP_CLIENT_EVENT_KEEP_ALIVE,
                .keep_alive = evt,
            };
        },
        [](ksnp_client_event_error evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type  = ksnp_client_event_type::KSNP_CLIENT_EVENT_ERROR,
                .error = evt,
            };
        },
    };
    return std::visit(visitor, event);
}

auto inline into_message(::ksnp_message msg) -> message_t
{
    switch (msg.type) {
    case ksnp_message_type::KSNP_MSG_ERROR:
        return msg.error;
    case ksnp_message_type::KSNP_MSG_VERSION:
        return msg.version;
    case ksnp_message_type::KSNP_MSG_OPEN_STREAM:
        return msg.open_stream;
    case ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY:
        return msg.open_stream_reply;
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM:
        return msg.close_stream;
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY:
        return msg.close_stream_reply;
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY:
        return msg.close_stream_notify;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM:
        return msg.suspend_stream;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY:
        return msg.suspend_stream_reply;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY:
        return msg.suspend_stream_notify;
    case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM:
        return msg.keep_alive_stream;
    case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY:
        return msg.keep_alive_stream_reply;
    case ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY:
        return msg.capacity_notify;
    case ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY:
        return msg.key_data_notify;
    default:
        throw exception(ksnp_error::KSNP_E_INVALID_MESSAGE_TYPE);
    }
}

auto inline into_event(ksnp_client_event event) -> std::optional<client_event>
{
    switch (event.type) {
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_NONE:
        return std::nullopt;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_HANDSHAKE:
        return event.handshake;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_OPEN:
        return event.stream_open;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_CLOSE:
        return event.stream_close;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_SUSPEND:
        return event.stream_suspend;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_KEY_DATA:
        return event.key_data;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_KEEP_ALIVE:
        return event.keep_alive;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_ERROR:
        return event.error;
    default:
        throw exception(ksnp_error::KSNP_E_INVALID_EVENT_TYPE);
    }
}

auto inline into_event(ksnp_server_event event) -> std::optional<server_event>
{
    switch (event.type) {
    case ksnp_server_event_type::KSNP_SERVER_EVENT_NONE:
        return std::nullopt;
    case ksnp_server_event_type::KSNP_SERVER_EVENT_HANDSHAKE:
        return event.handshake;
    case ksnp_server_event_type::KSNP_SERVER_EVENT_OPEN_STREAM:
        return event.open_stream;
    case ksnp_server_event_type::KSNP_SERVER_EVENT_CLOSE_STREAM:
        return event.close_stream;
    case ksnp_server_event_type::KSNP_SERVER_EVENT_SUSPEND_STREAM:
        return event.suspend_stream;
    case ksnp_server_event_type::KSNP_SERVER_EVENT_NEW_CAPACITY:
        return event.new_capacity;
    case ksnp_server_event_type::KSNP_SERVER_EVENT_KEEP_ALIVE:
        return event.keep_alive;
    case ksnp_server_event_type::KSNP_SERVER_EVENT_ERROR:
        return event.error;
    default:
        throw exception(ksnp_error::KSNP_E_INVALID_EVENT_TYPE);
    }
}

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
