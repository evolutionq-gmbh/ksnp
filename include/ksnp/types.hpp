#pragma once

#include <concepts>
#include <exception>
#include <source_location>
#include <string_view>

#include "ksnp/types.h"

namespace ksnp
{

/**
 * @brief Base class for exceptions in this library.
 *
 * @tparam Code Type of the error code associated with exceptions.
 */
template<std::copyable Code>
class base_exception : public std::exception
{
    Code                 error_code;
    char const          *desc;
    std::source_location loc;

public:
    /**
     * @brief Construct a new base exception object.
     *
     * @param error_code Error code associated with the exception.
     * @param location Source location associated with the exception.
     */
    explicit base_exception(Code error_code, std::source_location location = std::source_location::current())
        : error_code(error_code)
        , desc(nullptr)
        , loc(location)
    {}

    /**
     * @brief Construct a new base exception object.
     *
     * @param error_code Error code associated with the exception.
     * @param desc Description for the exception. This pointer must remain valid
     * for the lifetime of this object.
     * @param location Source location associated with the exception.
     */
    base_exception(Code error_code, char const *desc, std::source_location location = std::source_location::current())
        : error_code(error_code)
        , desc(desc)
        , loc(location)
    {}

    /** @brief Copy constructor. */
    base_exception(base_exception const &) = default;
    /** @brief Move constructor. */
    base_exception(base_exception &&)      = default;

    /** @brief Copy assignment operation. */
    auto operator=(base_exception const &) -> base_exception & = default;
    /** @brief Move assignment operation. */
    auto operator=(base_exception &&) -> base_exception &      = default;

    ~base_exception() override = default;

    /**
     * @brief Get the error code associated with this exception.
     *
     * @return Code Associated error code.
     */
    [[nodiscard]] auto code() const noexcept -> Code
    {
        return this->error_code;
    }

    /**
     * @brief Get the error description.
     *
     * @return Pointer to the error description.
     * @return nullptr if no description is available.
     */
    [[nodiscard]] auto description() const noexcept -> char const *
    {
        return this->desc;
    }

    /**
     * @brief Exception description.
     *
     * @see std::exception::what().
     * @return Pointer to the exception description.
     */
    [[nodiscard]] auto what() const noexcept -> char const * override
    {
        return this->desc != nullptr ? this->desc : "";
    }
};

/**
 * @brief General library exception.
 *
 * This exception is thrown if the library encounters an error not caused by
 * handling remote data.
 */
class exception : public base_exception<ksnp_error>
{
public:
    /**
     * @brief Construct a new exception object.
     *
     * @param error_code Library error code causing the exception.
     * @param location Source location associated with the exception.
     */
    explicit exception(ksnp_error error_code, std::source_location location = std::source_location::current())
        : base_exception<ksnp_error>(error_code, ksnp_error_description(error_code), location)
    {}

    /** Copy constructor. */
    exception(exception const &)                     = default;
    /** Move constructor. */
    exception(exception &&)                          = default;
    /** Copy assignment operator. */
    auto operator=(exception const &) -> exception & = default;
    /** Move assignment operator. */
    auto operator=(exception &&) -> exception &      = default;

    ~exception() override = default;
};

/**
 * @brief Protocol error exception.
 *
 * This exception is thrown if handling remote data has detected a protocol
 * error.
 */
class protocol_exception : public base_exception<ksnp_error_code>
{
public:
    using base_exception::base_exception;

    /**
     * @brief Construct a new exception object.
     *
     * @param protocol_error Protocol error code causing the exception.
     * @param location Source location associated with the exception.
     */
    explicit protocol_exception(ksnp_protocol_error  protocol_error,
                                std::source_location location = std::source_location::current())
        : base_exception(protocol_error.code, protocol_error.description, location)
    {}

    /** Copy constructor. */
    protocol_exception(protocol_exception const &)                     = default;
    /** Move constructor. */
    protocol_exception(protocol_exception &&)                          = default;
    /** Copy assignment operator. */
    auto operator=(protocol_exception const &) -> protocol_exception & = default;
    /** Move assignment operator. */
    auto operator=(protocol_exception &&) -> protocol_exception &      = default;

    ~protocol_exception() override = default;

    /**
     * @brief Exception description.
     *
     * @see std::exception::what().
     * @return Pointer to the exception description.
     */
    [[nodiscard]] auto what() const noexcept -> char const * override
    {
        return this->description() != nullptr ? this->description() : ksnp_protocol_error_description(this->code());
    }
};

/**
 * @brief Unsupported version exception.
 *
 * This exception is thrown if a remote connection uses an unsupported version.
 */
class version_exception : public std::exception
{
public:
    using std::exception::exception;

    /** Copy constructor. */
    version_exception(version_exception const &)                     = default;
    /** Move constructor. */
    version_exception(version_exception &&)                          = default;
    /** Copy assignment operator. */
    auto operator=(version_exception const &) -> version_exception & = default;
    /** Move assignment operator. */
    auto operator=(version_exception &&) -> version_exception &      = default;

    ~version_exception() override = default;
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
    /** @brief Type of the stored object. */
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

    /** @brief Move constructor. */
    unique_obj(unique_obj &&other) noexcept : object(other.object)
    {
        other.object = zero_val;
    }

    auto operator=(unique_obj const &) -> unique_obj & = delete;

    /** @brief Move assignment operator. */
    auto operator=(unique_obj &&other) noexcept -> unique_obj &
    {
        using std::swap;
        swap(this->object, other.object);
        return *this;
    }

    /**
     * @brief Assign an object to this instance.
     *
     * @param other_object Object to assign. The object is taken ownership of.
     * A previously stored object is destroyed.
     * @return Reference to this.
     */
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

}  // namespace ksnp
