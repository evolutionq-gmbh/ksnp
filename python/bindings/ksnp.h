#pragma once

#include <Python.h>

#include <stdexcept>

#include <ksnp/serde.h>
#include <ksnp/types.h>
#include <ksnp/types.hpp>
#include <nanobind/nanobind.h>

namespace pyksnp
{

// helper type for the visitor
template<class... Ts>
struct overloads : Ts... {
    using Ts::operator()...;
};

/**
 * @brief Wrapper for Py_buffer to handle lifetime management.
 *
 * The buffer must be one-dimensional and contiguous.
 *
 * @tparam RW Parameter indicating if the buffer is read-only or read-write.
 */
template<bool RW = false>
class pybuffer
{
private:
    Py_buffer view;

public:
    /**
     * @brief Create a buffer from a Python object that implements the buffer
     * API.
     *
     * @param object Object that supports the getbuffer call. The object must
     * provide a one-dimensional contiguous view.
     */
    explicit pybuffer(nanobind::handle const &object) : view{}
    {
        if (PyObject_GetBuffer(object.ptr(), &this->view, RW ? PyBUF_CONTIG : PyBUF_CONTIG_RO) != 0) {
            throw std::invalid_argument("non-contiguous view");
        }
    }

    pybuffer(pybuffer const &) = delete;
    pybuffer(pybuffer &&)      = delete;

    ~pybuffer() noexcept
    {
        PyBuffer_Release(&this->view);
    }

    auto operator=(pybuffer const &) -> pybuffer & = delete;
    auto operator=(pybuffer &&) -> pybuffer &      = delete;

    [[nodiscard]] auto data() const noexcept -> unsigned char const *
    {
        return static_cast<unsigned char const *>(view.buf);
    }

    [[nodiscard]] auto data() noexcept -> unsigned char *
    requires(RW)
    {
        return static_cast<unsigned char *>(view.buf);
    }

    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return static_cast<std::size_t>(view.len);
    }

    [[nodiscard]] auto cbegin() const noexcept -> unsigned char const *
    {
        return data();
    }

    [[nodiscard]] auto begin() const noexcept -> unsigned char const *
    {
        return data();
    }

    [[nodiscard]] auto begin() noexcept -> unsigned char *
    requires(RW)
    {
        return data();
    }

    [[nodiscard]] auto cend() const noexcept -> unsigned char const *
    {
        return data() + size();
    }

    [[nodiscard]] auto end() const noexcept -> unsigned char const *
    {
        return data() + size();
    }

    [[nodiscard]] auto end() noexcept -> unsigned char *
    requires(RW)
    {
        return data() + size();
    }
};

namespace serde
{
namespace messages
{
auto register_module(nanobind::module_ &mod) -> void;
}
auto register_module(nanobind::module_ &mod) -> void;
}  // namespace serde

namespace stream
{
auto register_module(nanobind::module_ &mod) -> void;
}

namespace client
{
namespace event
{
auto register_module(nanobind::module_ &mod) -> void;
}
auto register_module(nanobind::module_ &mod) -> void;
}  // namespace client

namespace server
{
namespace event
{
auto register_module(nanobind::module_ &mod) -> void;
}
auto register_module(nanobind::module_ &mod) -> void;
}  // namespace server

}  // namespace pyksnp

template<>
inline constexpr bool std::ranges::enable_borrowed_range<pyksnp::pybuffer<false>> = true;
template<>
inline constexpr bool std::ranges::enable_borrowed_range<pyksnp::pybuffer<true>> = true;
