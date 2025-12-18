/**
 * @file common.hpp
 * @author evolutionQ GmbH
 * @copyright Copyright (c) 2025
 *
 * @brief Common types and function for the client and server examples.
 */

#include <cassert>
#include <cerrno>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <netdb.h>
#include <optional>
#include <source_location>
#include <span>
#include <sys/poll.h>
#include <unistd.h>

#include "helpers.hpp"
#include "ksnp/client.h"
#include "ksnp/messages.h"
#include "ksnp/serde.h"
#include "ksnp/server.h"
#include "ksnp/types.h"

/// @brief Size of key chunks used by the examples.
static uint16_t const CHUNK_SIZE = 32;

static size_t const EXCEPTION_BUFFER_SIZE = 512;

/// @brief Static storage for exception messages.
static inline thread_local std::array<char, EXCEPTION_BUFFER_SIZE>
    exception_message_buffer{};  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

/**
 * @brief Exception that may be thrown as a result of some error code indicating
 * an error.
 *
 *
 */
template<typename E, auto fmt_error>
requires(std::copyable<E> && std::invocable<decltype(fmt_error), E>
#if __cplusplus >= 202302L
         && std::formattable<std::invoke_result_t<decltype(fmt_error), E>, char>
#endif
         )
class error_code_exception : public std::exception
{
private:
    E                    err;
    char const          *message;
    std::source_location loc;

public:
    explicit error_code_exception(E                    err,
                                  char const          *message  = nullptr,
                                  std::source_location location = std::source_location::current())
        : err(err)
        , message(message)
        , loc(location)
    {}

    /**
     * @brief Get the error code.
     *
     * @return The error code.
     */
    [[nodiscard]] auto error() const -> E
    {
        return this->err;
    }

    /**
     * @brief Get the location the exception was constructed with/at.
     *
     * @return The error location.
     */
    [[nodiscard]] auto location() const -> std::source_location const &
    {
        return this->loc;
    }

    /**
     * @brief Get a brief error description.
     *
     * @return C-string with an error description. Valid until `what` is called
     * on any other exception.
     */
    [[nodiscard]] auto what() const noexcept -> char const * override
    {
        if (this->message != nullptr) {
            auto const result = std::format_to_n(exception_message_buffer.begin(),
                                                 exception_message_buffer.size() - 1,
                                                 "{}:{} {}: {}\0",
                                                 loc.file_name(),
                                                 loc.line(),
                                                 this->message,
                                                 fmt_error(this->err));
            *result.out       = '\0';
        } else {
            auto const result = std::format_to_n(exception_message_buffer.begin(),
                                                 exception_message_buffer.size() - 1,
                                                 "{}:{}: {}\0",
                                                 loc.file_name(),
                                                 loc.line(),
                                                 fmt_error(this->err));
            *result.out       = '\0';
        }
        return exception_message_buffer.data();
    }
};

/**
 * @brief Exception that may be thrown as a result of some key stream operation
 * returning an error.
 */
class ksnp_exception : public error_code_exception<ksnp_error, ksnp_error_description>
{
public:
    using error_code_exception::error_code_exception;
};

/**
 * @brief Exception that may be thrown as a result of some key stream operation
 * returning an error.
 */
class ksnp_status_exception : public error_code_exception<ksnp_status_code, ksnp_status_code_description>
{
public:
    using error_code_exception::error_code_exception;
};

/**
 * @brief Check if the result of an API call is an error, and throw an exception
 * if so.
 *
 * @param err Error value to check.
 * @param location Location where the check is performed, defaults to the call
 * site.
 */
inline void check_error(ksnp_error err, std::source_location const &location = std::source_location::current())
{
    if (err != ksnp_error::KSNP_E_NO_ERROR) {
        throw ksnp_exception(err, nullptr, location);
    }
}

/**
 * @brief Exception that may be thrown as a result of `errno` being nonzero.
 */
class errno_exception : public error_code_exception<int, strerror>
{
public:
    using error_code_exception::error_code_exception;
};

/**
 * @brief Check if the result of an C library call is an error, and throw an
 * exception if so.
 *
 * @param retval Error value to check.
 * @param message Additional error message to log.
 * @param location Location where the check is performed, defaults to the call
 * site.
 */
inline auto check_errno(int                         retval,
                        char const                 *message  = nullptr,
                        std::source_location const &location = std::source_location::current()) -> int
{
    if (retval < 0) {
        throw errno_exception(errno, message, location);
    }
    return retval;
}

/**
 * @brief Exception that may be thrown as a result of `errno` being nonzero.
 */
class gai_exception : public error_code_exception<int, gai_strerror>
{
public:
    using error_code_exception::error_code_exception;
};

/**
 * @brief Concept for a type able to processing I/O data and convert it into
 * type-specific events.
 *
 * This concept maps to the server and client types, as well as a raw message
 * processor.
 *
 * @tparam T Type purported to implement IoProcessor.
 */
template<typename T>
concept IoProcessor =
    requires(T impl, std::span<unsigned char const> cdata, std::span<unsigned char> data, ksnp_close_direction dir) {
        typename T::result_type;

        { std::constructible_from<bool, typename T::result_type const &> };

        { impl.want_read() } -> std::same_as<bool>;

        { impl.want_write() } -> std::same_as<bool>;

        { impl.read_data(cdata) } -> std::convertible_to<size_t>;

        { impl.flush_data() } -> std::same_as<void>;

        { impl.write_data(data) } -> std::convertible_to<size_t>;

        { impl.next_event() } -> std::same_as<typename T::result_type>;

        { impl.close_connection(dir) } -> std::same_as<void>;
    };

/**
 * @brief Wrapper for message_context.
 */
class message_context_t : public ksnp::unique_obj<ksnp_message_context *, ksnp_message_context_destroy>
{
public:
    using result_type = std::optional<ksnp::message_t>;

    message_context_t() : unique_obj(nullptr)
    {
        check_error(ksnp_message_context_create(&this->get()));
    }

    message_context_t(ksnp_buffer *read_buffer, ksnp_buffer *write_buffer) : unique_obj(nullptr)
    {
        check_error(ksnp_message_context_create_with_buffer(&this->get(), read_buffer, write_buffer));
    }

    auto want_read() -> bool
    {
        return ::ksnp_message_context_want_read(**this);
    }

    auto want_write() -> bool
    {
        return ::ksnp_message_context_want_write(**this);
    }

    auto read_data(std::span<unsigned char const> data) -> size_t
    {
        size_t len = data.size();
        check_error(::ksnp_message_context_read_data(**this, data.data(), &len));
        return len;
    }

    auto write_data(std::span<unsigned char> data) -> size_t
    {
        size_t len = data.size();
        check_error(::ksnp_message_context_write_data(**this, data.data(), &len));
        return len;
    }

    auto next_event() -> result_type
    {
        ksnp_message const *msg;
        ksnp_protocol_error protocol_error{};
        if (auto err = ::ksnp_message_context_next_message(**this, &msg, &protocol_error);
            err != ksnp_error::KSNP_E_NO_ERROR) {
            if (err == ksnp_error::KSNP_E_PROTOCOL_ERROR) {
                throw ksnp::protocol_exception(protocol_error);
            }
            throw ksnp_exception(err);
        }

        if (msg == nullptr) {
            return std::nullopt;
        }
        return ksnp::into_message(*msg);
    }

    void write_message(ksnp_message const *msg)
    {
        check_error(::ksnp_message_context_write_message(**this, msg));
    }
};

class client_obj : public ksnp::unique_obj<ksnp_client *, ksnp_client_destroy>
{
public:
    using result_type = std::optional<ksnp::client_event>;

    explicit client_obj(message_context_t &ctx) : unique_obj(nullptr)
    {
        check_error(ksnp_client_create(&this->get(), ctx.get()));
    }

    auto want_read() -> bool
    {
        return ::ksnp_client_want_read(**this);
    }

    auto want_write() -> bool
    {
        return ::ksnp_client_want_write(**this);
    }

    auto read_data(std::span<unsigned char const> data) -> size_t
    {
        size_t len = data.size();
        check_error(::ksnp_client_read_data(**this, data.data(), &len));
        return len;
    }

    void flush_data()
    {
        check_error(::ksnp_client_flush_data(**this));
    }

    auto write_data(std::span<unsigned char> data) -> size_t
    {
        size_t len = data.size();
        check_error(::ksnp_client_write_data(**this, data.data(), &len));
        return len;
    }

    auto next_event() -> result_type
    {
        ksnp_client_event evt{};
        check_error(::ksnp_client_next_event(**this, &evt));
        return ksnp::into_event(evt);
    }

    void open_stream(struct ksnp_stream_open_params const &params)
    {
        check_error(::ksnp_client_open_stream(**this, &params));
    }

    void close_stream()
    {
        check_error(::ksnp_client_close_stream(**this));
    }

    void suspend_stream(uint32_t timeout)
    {
        check_error(::ksnp_client_suspend_stream(**this, timeout));
    }

    void add_capacity(uint32_t additional_capacity)
    {
        check_error(::ksnp_client_add_capacity(**this, additional_capacity));
    }

    void close_connection(ksnp_close_direction dir)
    {
        check_error(::ksnp_client_close_connection(**this, dir));
    }
};

class server_obj : public ksnp::unique_obj<ksnp_server *, ksnp_server_destroy>
{
public:
    using result_type = std::optional<ksnp::server_event>;

    explicit server_obj(message_context_t &ctx) : unique_obj(nullptr)
    {
        check_error(ksnp_server_create(&this->get(), ctx.get()));
    }

    auto want_read() -> bool
    {
        return ::ksnp_server_want_read(**this);
    }

    auto want_write() -> bool
    {
        return ::ksnp_server_want_write(**this);
    }

    auto read_data(std::span<unsigned char const> data) -> size_t
    {
        size_t len = data.size();
        check_error(::ksnp_server_read_data(**this, data.data(), &len));
        return len;
    }

    void flush_data()
    {
        check_error(::ksnp_server_flush_data(**this));
    }

    auto write_data(std::span<unsigned char> data) -> size_t
    {
        size_t len = data.size();
        check_error(::ksnp_server_write_data(**this, data.data(), &len));
        return len;
    }

    auto next_event() -> result_type
    {
        ksnp_server_event evt{};
        check_error(::ksnp_server_next_event(**this, &evt));
        return ksnp::into_event(evt);
    }

    auto get_stream() -> ksnp_stream *
    {
        return ::ksnp_server_current_stream(**this);
    }

    void open_stream_ok(struct ksnp_stream *stream, struct ksnp_stream_accepted_params const &params)
    {
        check_error(::ksnp_server_open_stream_ok(**this, stream, &params));
    }

    void open_stream_fail(ksnp_status_code reason, struct ksnp_stream_qos_params const *params, char const *message)
    {
        check_error(::ksnp_server_open_stream_fail(**this, reason, params, message));
    }

    auto close_stream() -> struct ksnp_stream *
    {
        struct ksnp_stream *stream = nullptr;
        check_error(::ksnp_server_close_stream(**this, &stream));
        return stream;
    }

    auto suspend_stream_ok(uint32_t timeout) -> ksnp_stream *
    {
        struct ksnp_stream *stream = nullptr;
        check_error(::ksnp_server_suspend_stream_ok(**this, timeout, &stream));
        return stream;
    }

    void suspend_stream_fail(ksnp_status_code reason, char const *message)
    {
        check_error(::ksnp_server_suspend_stream_fail(**this, reason, message));
    }

    void keep_alive_ok()
    {
        check_error(::ksnp_server_keep_alive_ok(**this));
    }

    auto keep_alive_fail(ksnp_status_code reason, char const *message)
    {
        check_error(::ksnp_server_keep_alive_fail(**this, reason, message));
    }

    void close_connection(ksnp_close_direction dir)
    {
        check_error(::ksnp_server_close_connection(**this, dir));
    }
};

/**
 * @brief Wrapper for file descriptors.
 *
 * Note that no check is made on the return value of close. Use fd::release()
 * if a check is required.
 */
class fd : public ksnp::unique_obj<int, ::close, -1>
{
    using unique_obj::unique_obj;
};

/**
 * @brief Open a socket and connect to the host specified by the given host and
 * port.
 *
 * @param host Name of the host to connect to.
 * @param port_spec Port number as a string to connect to.
 * @return A socket connected to the given host.
 * @exception std::exception Throws an exception if no connection could be
 * created.
 */
auto connect(char const *host, char const *port_spec) -> fd;

/**
 * @brief Open a socket and bind to the given address and port.
 *
 * @param addr IP address to bind to.
 * @param port_spec Port number as a string to bind to.
 * @param queue_size Size of the listen queue.
 * @return A socket bound to the given address.
 * @exception std::exception Throws an exception if no bound socket could be
 * created.
 */
auto listen(char const *addr, char const *port_spec, int queue_size = 1) -> fd;

/**
 * @brief Simple fixed-size buffer with a filled part and a free part.
 *
 * This buffer is intended to be used in situations where data is read from and
 * written into be separate functions, and the resulting offsets are used to
 * adjust the buffer's instance.
 *
 * To use the buffer, use buffer::remaining() to get a writeable buffer chunk.
 * After writing to this chunk, use buffer::fill() to grow the buffer by the
 * count of written bytes. Then, use buffer::filled() to get the available
 * buffer chunk. After reading from the chunk, use buffer::consume() to remove
 * the number of bytes read from the front of the buffer.
 */
class buffer
{
private:
    /// @brief Pointer to buffer.
    std::span<unsigned char> storage;
    /// @brief Number of bytes in the buffer available for reading.
    size_t                   filled_count;

public:
    /**
     * @brief Construct a new buffer with the given capacity.
     *
     * @param capacity Size of the buffer in bytes.
     */
    explicit buffer(size_t capacity) : storage(new unsigned char[capacity], capacity), filled_count(0)
    {}

    buffer(buffer const &) = delete;
    buffer(buffer &&other) noexcept : storage(other.storage), filled_count(other.filled_count)
    {
        other.storage = {};
    }

    ~buffer()
    {
        delete[] this->storage.data();
    }

    auto operator=(buffer const &) -> buffer & = delete;
    auto operator=(buffer &&other) noexcept -> buffer &
    {
        using std::swap;
        swap(this->storage, other.storage);
        swap(this->filled_count, other.filled_count);
        return *this;
    }

    /**
     * @brief Return the remaining capacity.
     *
     * @return Size in bytes of the remaining capacity.
     */
    [[nodiscard]] auto remaining_size() const -> size_t
    {
        return this->storage.size() - this->filled_count;
    }

    /**
     * @brief Return the buffer's remaining space.
     *
     * @return Span of the remaining space.
     */
    [[nodiscard]] auto remaining() const -> std::span<unsigned char>
    {
        return this->storage.subspan(this->filled_count);
    }

    /**
     * @brief Return a pointer to the buffer's storage.
     *
     * @return Pointer to the storage of the buffer.
     */
    [[nodiscard]] auto data() const -> unsigned char const *
    {
        return this->storage.data();
    }

    /**
     * @brief Return a pointer to the buffer's storage.
     *
     * @return Pointer to the storage of the buffer.
     */
    auto data() -> unsigned char *
    {
        return this->storage.data();
    }

    /**
     * @brief Return the number of bytes written to the buffer.
     *
     * @return Size of the written buffer's space in bytes.
     */
    [[nodiscard]] auto size() const -> size_t
    {
        return this->filled_count;
    }

    /**
     * @brief Return the buffer's filled space.
     *
     * @return Span of the filled buffer.
     */
    auto filled() -> std::span<unsigned char>
    {
        return this->storage.first(this->filled_count);
    }

    /**
     * @brief Check if the buffer contains data.
     *
     * @return true if the buffer has at least one written byte.
     * @return false if the buffer is empty.
     */
    [[nodiscard]] auto empty() const -> bool
    {
        return this->filled_count == 0;
    }

    /**
     * @brief Check if the buffer has remaining capacity.
     *
     * @return true if the buffer is full and has no further capacity.
     * @return false if some capacity is remaining.
     */
    [[nodiscard]] auto full() const -> bool
    {
        return this->filled_count == this->storage.size();
    }

    /**
     * @brief Change the size of the filled portion of the buffer.
     *
     * @param count Number of bytes to grow the filled section by. This must not
     * exceed remaining_size().
     */
    void fill(size_t count)
    {
        assert(this->filled_count + count <= this->storage.size());
        this->filled_count += count;
    }

    /**
     * @brief Remove the front @p count bytes from the buffer.
     *
     * The written contents of the buffer are shifted towards the beginning.
     *
     * @param count Number of bytes to consume. This must not exceed filled().
     */
    void consume(size_t count)
    {
        assert(count <= this->filled_count);
        std::ranges::copy(this->storage.subspan(count), this->storage.begin());
        this->filled_count -= count;
    }
};

/**
 * @brief A template class that implements some of the common behavior between
 * a client and server connection.
 *
 * This class can read and write data using a socket, manage the buffering of
 * that data and translate it into client or server events.
 *
 * Of main interest is connection_handler::next_event(), which can be used to
 * implement concrete event loops.
 *
 * @tparam T A type for a client or server that supports IoProcessor.
 */
template<typename T>
requires(IoProcessor<T>)
class connection_handler
{
    fd                  sock;
    ksnp::vector_buffer read_buffer;
    ksnp::vector_buffer write_buffer;

    message_context_t msg_context;
    T                 conn;

public:
    explicit connection_handler(fd sock)
        : sock(std::move(sock))
        , msg_context(this->read_buffer.ksnp_buffer_ptr(), this->write_buffer.ksnp_buffer_ptr())
        , conn(T(this->msg_context))
    {
        this->read_buffer.reserve(KSNP_MAX_MSG_LEN);
        this->write_buffer.reserve(KSNP_MAX_MSG_LEN);
    }

    connection_handler(connection_handler const &) = delete;
    connection_handler(connection_handler &&)      = delete;

    virtual ~connection_handler() noexcept = default;

    auto operator=(connection_handler const &) -> connection_handler & = delete;
    auto operator=(connection_handler &&) -> connection_handler &      = delete;

    /**
     * @brief Get a pointer to the embedded client or server connection.
     *
     * @return A pointer to the client or server connection.
     */
    auto connection() -> T &
    {
        return this->conn;
    }

    /**
     * @brief Perform I/O until an event is generated.
     *
     * @param timeout Maximum amount of time to wait for I/O. If not set, I/O
     * operations can block indefinitely.
     * @return The next event, or `nullopt` if the connection has terminated.
     */
    auto
    next_event(std::optional<unsigned int> timeout = std::nullopt)  // NOLINT(readability-function-cognitive-complexity)
        -> typename T::result_type
    {
        // Track if some read or write operation is blocked on socket I/O. Note
        // that these values persist across I/O loop iterations.
        bool wait_read  = false;
        bool wait_write = false;

        // The main I/O loop. This will run until an event occurs, an error
        // occurs, or no further I/O needs to be performed (because the
        // connection has closed).
        while (true) {
io_loop_start:
            // Write all pending data until no further data is pending, or the
            // socket is blocked.
            while (!wait_write && conn.want_write()) {
                conn.flush_data();
                // Move data from the egress buffer to the socket.
                auto count = ::write(*sock, write_buffer.data(), write_buffer.size());
                if (count == -1) {
                    if (errno != EWOULDBLOCK) {
                        throw errno_exception(errno, "Failed to write to socket");
                    }
                    wait_write = true;
                    break;
                }
                assert(count > 0);
                write_buffer.erase(write_buffer.begin(), write_buffer.begin() + count);
            }

            // Read all data from the socket until no further data is available,
            // or the input buffer no longer requires more data to progress.
            while (!wait_read && conn.want_read()) {
                // If no ingress data is buffered, read some from the socket.
                auto orig_len = read_buffer.size();
                read_buffer.resize(read_buffer.capacity());

                try {
                    auto count = ::read(*sock, read_buffer.data() + orig_len, read_buffer.size() - orig_len);
                    if (count == -1) {
                        if (errno != EWOULDBLOCK) {
                            throw errno_exception(errno, "Failed to read from socket");
                        }
                        wait_read = true;
                        read_buffer.resize(orig_len);
                        break;
                    } else if (count == 0) {  // NOLINT(readability-else-after-return)
                        read_buffer.resize(orig_len);
                        std::cout << "Remote closed the connection\n";
                        // If reading from the socket indicates EOF, inform the
                        // client/server connection.
                        conn.close_connection(ksnp_close_direction::KSNP_CLOSE_READ);
                        break;
                    } else {
                        read_buffer.resize(orig_len + count);
                    }

                } catch (...) {
                    read_buffer.resize(orig_len);
                    throw;
                }
            }

            if (!conn.want_read()) {
                // Check if an event occurs after processing. If so, check
                // if it can be handled by the connection wrapper directly.
                // If not, return it.
                auto evt = conn.next_event();
                if (evt) {
                    if (!this->process_event(evt)) {
                        return evt;
                    }
                    // Events may generate data, or more than one event may be
                    // pending.
                    goto io_loop_start;  // NOLINT(cppcoreguidelines-avoid-goto, hicpp-avoid-goto)
                }
            }

            // If the connection does not want more data (despite not generating
            // an event) and has nothing to write, no further I/O needs to
            // occur. In that case, close the socket and return nullopt.
            if (!conn.want_read() && write_buffer.empty()) {
                (void)shutdown(*this->sock, SHUT_WR);
                this->sock.reset();
                return std::nullopt;
            }

            // One write/read I/O cycle complete. Note that reading data may
            // trigger more data to write, but that can be handled on the next
            // iteration, hence the continue below.

            // Collect events of interest.
            short events = 0;
            if (wait_read) {
                events |= POLLIN;
            }
            if (wait_write) {
                events |= POLLOUT;
            }
            if (events == 0) {
                continue;
            }

            // Poll for additional I/O capacity.
            struct pollfd pfd{.fd = *sock, .events = events, .revents = 0};
            int           poll_timeout;
            if (timeout.has_value()) {
                poll_timeout = static_cast<int>(*timeout);
            } else {
                poll_timeout = -1;
            }
            auto poll_count = check_errno(poll(&pfd, 1, poll_timeout), "poll failed");
            if (poll_count == 0) {
                throw errno_exception(ETIMEDOUT);
            }

            if ((pfd.revents & POLLIN) != 0) {
                wait_read = false;
            }
            if ((pfd.revents & POLLOUT) != 0) {
                wait_write = false;
            }
            if ((pfd.revents & POLLERR) != 0) {
                int       error  = 0;
                socklen_t errlen = sizeof(error);
                getsockopt(*sock, SOL_SOCKET, SO_ERROR, static_cast<void *>(&error), &errlen);
                std::cerr << "Socket error: " << strerror(error) << '\n';
                return std::nullopt;
            }
        }
    }

protected:
    /**
     * @brief Process the given event and act on it as appropriate.
     *
     * A client or server may know how to handle an event, which it can do in
     * the implementation of this method. Otherwise, this method may return
     * false and the event is forwarded to the user of the client or server.
     *
     * @param evt Event to process.
     * @return true If the event was processed and needs not to be forwarded.
     * @return false If the event could not be processed and needs to be
     * forwarded.
     */
    virtual auto process_event(typename T::result_type &evt) -> bool = 0;
};
