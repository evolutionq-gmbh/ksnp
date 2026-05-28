#pragma once

#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>

#include <ksnp/messages.h>
#include <ksnp/serde.hpp>
#include <ksnp/types.h>
#include <nanobind/nanobind.h>

#include "ksnp/serde.h"
#include "stream.h"

namespace pyksnp::serde
{

namespace nb = nanobind;

namespace messages
{

class open_stream
{
public:
    pyksnp::stream::open_params parameters;

    explicit open_stream(pyksnp::stream::open_params parameters) : parameters(std::move(parameters))
    {}

    explicit open_stream(ksnp_msg_open_stream msg) : parameters(msg.parameters)
    {}
};

class open_stream_reply
{
public:
    ksnp_status_code                                                                         code;
    std::optional<std::variant<pyksnp::stream::accepted_params, pyksnp::stream::qos_params>> parameters;
    nb::str                                                                                  message;

    open_stream_reply(
        ksnp_status_code                                                                         code,
        std::optional<std::variant<pyksnp::stream::accepted_params, pyksnp::stream::qos_params>> parameters,
        nb::str                                                                                  message)
        : code(code)
        , parameters(std::move(parameters))
        , message(std::move(message))
    {}

    explicit open_stream_reply(ksnp_msg_open_stream_reply msg) : code(msg.code), message(msg.message)
    {
        if (msg.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
            this->parameters = pyksnp::stream::accepted_params(msg.parameters.reply);
        } else if (msg.parameters.qos != nullptr) {
            this->parameters = pyksnp::stream::qos_params(msg.parameters.qos);
        }
    }
};

class close_stream_notify
{
public:
    ksnp_status_code code;
    nb::str          message;

    close_stream_notify(ksnp_status_code code, nb::str message) : code(code), message(std::move(message))
    {}

    explicit close_stream_notify(ksnp_msg_close_stream_notify msg) : code(msg.code), message(msg.message)
    {}
};

class suspend_stream_reply
{
public:
    ksnp_status_code code;
    uint32_t         timeout;
    nb::str          message;

    suspend_stream_reply(ksnp_status_code code, uint32_t timeout, nb::str message)
        : code(code)
        , timeout(timeout)
        , message(std::move(message))
    {}

    explicit suspend_stream_reply(ksnp_msg_suspend_stream_reply msg)
        : code(msg.code)
        , timeout(msg.timeout)
        , message(msg.message)
    {}
};

class keep_alive_stream_reply
{
public:
    ksnp_status_code code;
    nb::str          message;

    keep_alive_stream_reply(ksnp_status_code code, nb::str message) : code(code), message(std::move(message))
    {}

    explicit keep_alive_stream_reply(ksnp_msg_keep_alive_stream_reply msg) : code(msg.code), message(msg.message)
    {}
};

class key_data_notify
{
public:
    nb::bytes key_data;

    explicit key_data_notify(nb::bytes key_data) : key_data(std::move(key_data))
    {}

    explicit key_data_notify(ksnp_msg_key_data_notify msg) : key_data(msg.key_data.data, msg.key_data.len)
    {}
};

}  // namespace messages

/**
 * @brief Wrapper for ksnp_buffer that automatically handles type conversion.
 *
 * @tparam T The class that implements the buffer. This is a CRTP parameter,
 * and must be of a child class.
 */
template<typename T>
class generic_buffer : private ksnp_buffer
{
    friend T;

public:
    generic_buffer(generic_buffer const &) = delete;

    auto operator=(generic_buffer const &) -> generic_buffer & = delete;

    ~generic_buffer() = default;

    auto as_buffer_ptr() -> ksnp_buffer *
    {
        return this;
    }

private:
    generic_buffer()
        : ksnp_buffer{.contents  = contents_fn,
                      .consume   = consume_fn,
                      .append    = append_fn,
                      .truncate  = truncate_fn,
                      .user_data = this}
    {}

    generic_buffer(generic_buffer &&other) noexcept : ksnp_buffer(other)
    {
        this->user_data = this;  // NOLINT(cppcoreguidelines-prefer-member-initializer)
    }

    auto operator=(generic_buffer &&other) noexcept -> generic_buffer &
    {
        static_cast<ksnp_buffer &>(*this) = static_cast<ksnp_buffer &>(other);
        this->user_data                   = this;
        return *this;
    }

    static auto from_buffer_ptr(ksnp_buffer *base_buffer) -> T *
    {
        return static_cast<T *>(static_cast<generic_buffer<T> *>(base_buffer->user_data));
    }

    static auto from_buffer_ptr(ksnp_buffer const *base_buffer) -> T const *
    {
        return static_cast<T const *>(static_cast<generic_buffer<T> const *>(base_buffer->user_data));
    }

    static void contents_fn(struct ksnp_buffer *buffer, struct ksnp_data *data) noexcept
    try {
        auto contents = from_buffer_ptr(buffer)->contents();
        data->data    = contents.data();
        data->len     = contents.size();
    } catch (nb::python_error &e) {
        e.discard_as_unraisable(__func__);
    } catch (...) {  // NOLINT(bugprone-empty-catch)
    }

    static void consume_fn(struct ksnp_buffer *buffer, size_t count) noexcept
    try {
        from_buffer_ptr(buffer)->consume(count);
    } catch (nb::python_error &e) {
        e.discard_as_unraisable(__func__);
    } catch (...) {  // NOLINT(bugprone-empty-catch)
    }

    static auto append_fn(struct ksnp_buffer  *buffer,
                          unsigned char const *data,
                          size_t              *len) noexcept  // NOLINT(readability-non-const-parameter)
        -> ksnp_error
    try {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        std::span contents(data, *len);
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
        size_t count = from_buffer_ptr(buffer)->append(contents);
        *len         = count;
        return ksnp_error::KSNP_E_NO_ERROR;
    } catch (nb::python_error &e) {
        e.discard_as_unraisable(__func__);
        return ksnp_error::KSNP_E_UNKNOWN;
    } catch (std::bad_alloc const &) {
        return ksnp_error::KSNP_E_NO_MEM;
    } catch (...) {
        return ksnp_error::KSNP_E_UNKNOWN;
    }

    static void truncate_fn(struct ksnp_buffer *buffer, size_t size) noexcept
    try {
        from_buffer_ptr(buffer)->truncate(size);
    } catch (nb::python_error &e) {
        e.discard_as_unraisable(__func__);
    } catch (...) {  // NOLINT(bugprone-empty-catch)
    }
};

/**
 * @brief Buffer using a Python bytearray for storage.
 */
class bytearray_buffer : public generic_buffer<bytearray_buffer>
{
private:
    nb::bytearray storage;

public:
    explicit bytearray_buffer(nb::bytearray arr) : storage(std::move(arr))
    {}

    auto contents() -> std::span<unsigned char>
    {
        auto *data = static_cast<unsigned char *>(this->storage.data());
        auto  size = this->storage.size();
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        return {data, size};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    }

    void consume(size_t count)
    {
        auto contents = this->contents();
        std::ranges::move(contents.subspan(count), contents.data());
        this->storage.resize(contents.size() - count);
    }

    auto append(std::span<unsigned char const> data) -> size_t
    {
        auto old_size = this->storage.size();
        this->storage.resize(old_size + data.size());
        std::ranges::copy(data, this->contents().subspan(old_size).begin());
        return data.size();
    }

    void truncate(size_t size)
    {
        this->storage.resize(size);
    }

private:
};

/**
 * @brief Base class for buffers that can be implemented by deriving Python
 * classes.
 *
 * The methods ending with _py are intended to be overridden. The default
 * implementation acts as if the buffer is empty and cannot grow.
 */
class buffer
    : public nb::intrusive_base
    , public generic_buffer<buffer>
{
private:
    mutable std::optional<pybuffer<true>> last_view;

public:
    explicit buffer() = default;

    buffer(buffer const &) = delete;
    buffer(buffer &&)      = delete;

    ~buffer() override = default;

    auto operator=(buffer const &) -> buffer & = delete;
    auto operator=(buffer &&) -> buffer &      = delete;

    [[nodiscard]] virtual auto contents_py() const -> nb::memoryview
    {
        return nb::memoryview{nb::bytes("")};
    }

    virtual auto consume_py(std::size_t /*count*/) -> void
    {}

    virtual auto append_py(nb::memoryview const & /*data*/) -> std::size_t  // NOLINT, ignore no_return
    {
        throw std::bad_alloc();
    }

    virtual auto truncate_py(std::size_t /*size*/) -> void
    {}

    auto contents() -> std::span<unsigned char>
    {
        this->last_view.emplace(this->contents_py());
        return {*this->last_view};
    }

    auto consume(size_t count) -> void
    {
        this->last_view.reset();
        this->consume_py(count);
    }

    auto append(std::span<unsigned char const> data) -> size_t
    {
        this->last_view.reset();
        PyObject *view = PyMemoryView_FromMemory(const_cast<char *>(reinterpret_cast<char const *>(data.data())),
                                                 static_cast<Py_ssize_t>(data.size()),
                                                 PyBUF_READ);
        if (view == nullptr) {
            throw std::runtime_error("unable to create view");
        }
        return this->append_py(nb::memoryview(view));
    }

    auto truncate(size_t size) -> void
    {
        this->last_view.reset();
        this->truncate_py(size);
    }
};

/**
 * @brief Trampoline class for nanobind to dispatch virtual methods.
 */
class buffer_trampoline : buffer
{
    NB_TRAMPOLINE(buffer, 4);

public:
    explicit buffer_trampoline() = default;

    [[nodiscard]] auto contents_py() const noexcept -> nb::memoryview override
    {
        // NOLINTNEXTLINE
        NB_OVERRIDE(contents_py);
    }

    auto consume_py(size_t count) -> void override
    {
        // NOLINTNEXTLINE
        NB_OVERRIDE(consume_py, count);
    }

    auto append_py(nb::memoryview const &data) -> size_t override
    {
        // NOLINTNEXTLINE
        NB_OVERRIDE(append_py, data);
    }

    auto truncate_py(size_t len) -> void override
    {
        // NOLINTNEXTLINE
        NB_OVERRIDE(truncate_py, len);
    }
};

using message = std::variant<ksnp_msg_error,
                             ksnp_msg_version,
                             messages::open_stream,
                             messages::open_stream_reply,
                             ksnp_msg_close_stream,
                             ksnp_msg_close_stream_reply,
                             messages::close_stream_notify,
                             ksnp_msg_suspend_stream,
                             messages::suspend_stream_reply,
                             ksnp_msg_suspend_stream_notify,
                             ksnp_msg_keep_alive_stream,
                             messages::keep_alive_stream_reply,
                             ksnp_msg_capacity_notify,
                             messages::key_data_notify>;

/**
 * @brief Wrapper for ksnp::message_context to interface with Python.
 */
class message_context
{
private:
    std::unique_ptr<bytearray_buffer> read_buffer;
    std::unique_ptr<bytearray_buffer> write_buffer;
    ksnp::message_context             context;

public:
    message_context() : read_buffer(nullptr), write_buffer(nullptr)
    {}

    message_context(nb::bytearray read_buffer, nb::bytearray write_buffer)
        : read_buffer(new bytearray_buffer(std::move(read_buffer)))
        , write_buffer(new bytearray_buffer(std::move(write_buffer)))
        , context(this->read_buffer->as_buffer_ptr(), this->write_buffer->as_buffer_ptr())
    {}

    message_context(buffer &read_buffer, buffer &write_buffer)
        : read_buffer(nullptr)
        , write_buffer(nullptr)
        , context(read_buffer.as_buffer_ptr(), write_buffer.as_buffer_ptr())
    {}

    auto get_context() -> ksnp::message_context &
    {
        return this->context;
    }

    auto get_read_buffer() -> bytearray_buffer &
    {
        return *this->read_buffer;
    }

    auto get_write_buffer() -> bytearray_buffer &
    {
        return *this->write_buffer;
    }

    auto want_read() -> bool
    {
        return this->context.want_read();
    }

    auto want_write() -> bool
    {
        return this->context.want_write();
    }

    auto read_data(nb::memoryview const &buffer) -> size_t
    {
        pybuffer<false> view(buffer);
        return this->context.read_data(view);
    }

    auto write_data(nb::memoryview const &buffer) -> size_t
    {
        pybuffer<true> view(buffer);
        return this->context.write_data(view);
    }

    auto next_event() -> std::optional<message>;

    auto write_message(message const &msg) -> void;
};

}  // namespace pyksnp::serde
