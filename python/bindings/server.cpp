
#include <Python.h>

#include <optional>
#include <utility>
#include <variant>

#include <ksnp/server.hpp>
#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/tuple.h>
#include <nanobind/stl/variant.h>

// Make sure this headers follows nanobind.h
#include <nanobind/intrusive/ref.h>

#include "ksnp.h"
#include "serde.h"
#include "stream.h"

namespace pyksnp::server
{

namespace nb = nanobind;

namespace event
{

using pyksnp::stream::stream;

class event_open_stream
{
public:
    pyksnp::stream::open_params parameters;

    explicit event_open_stream(ksnp_server_event_open_stream event) : parameters(event.parameters)
    {}
};

class event_close_stream
{
    nb::ref<class stream> stream;

public:
    explicit event_close_stream(ksnp_server_event_close_stream event) : stream(stream::from_stream_ptr(event.stream))
    {
        // Remove the ref held by KSNP
        stream->dec_ref();
    }

    [[nodiscard]] auto get_stream() const -> nb::ref<class stream>
    {
        return this->stream;
    }
};

class server_event_error
{
public:
    ksnp_error_code       code;
    nb::str               description;
    nb::ref<class stream> stream;

    explicit server_event_error(ksnp_server_event_error event)
        : code(event.code)
        , description((event.description != nullptr) ? event.description : "")
    {
        if (event.stream != nullptr) {
            this->stream = stream::from_stream_ptr(event.stream);
            // Remove the ref held by KSNP
            stream->dec_ref();
        }
    }

    [[nodiscard]] auto get_stream() const -> nb::ref<class stream>
    {
        return this->stream;
    }
};

using server_event = std::variant<ksnp_server_event_handshake,
                                  event_open_stream,
                                  event_close_stream,
                                  ksnp_server_event_suspend_stream,
                                  ksnp_server_event_keep_alive,
                                  ksnp_server_event_new_capacity,
                                  server_event_error>;

namespace
{
auto convert(ksnp::server_event event) -> event::server_event
{
    auto const visitor = overloads{
        [](ksnp_server_event_open_stream evt) -> event::server_event {
            return event::event_open_stream(evt);
        },
        [](ksnp_server_event_close_stream evt) -> event::server_event {
            return event::event_close_stream(evt);
        },
        [](ksnp_server_event_error evt) -> event::server_event {
            return event::server_event_error(evt);
        },
        [](auto &&evt) -> event::server_event {
            return evt;
        },
    };
    return std::visit(visitor, event);
}

}  // namespace

auto register_module(nb::module_ &mod) -> void
{
    using namespace nb::literals;

    nb::class_<ksnp_server_event_handshake>(mod, "Handshake")
        .def_ro("protocol", &ksnp_server_event_handshake::protocol);

    nb::class_<event::event_open_stream>(mod, "OpenStream").def_ro("parameters", &event::event_open_stream::parameters);

    nb::class_<event::event_close_stream>(mod, "CloseStream")
        .def_prop_ro("stream", &event::event_close_stream::get_stream);

    nb::class_<ksnp_server_event_suspend_stream>(mod, "SuspendStream")
        .def_ro("timeout", &ksnp_server_event_suspend_stream::timeout);

    nb::class_<ksnp_server_event_keep_alive>(mod, "KeepAlive")
        .def_prop_ro("stream_id", [](ksnp_server_event_keep_alive const &self) -> pyksnp::stream::stream_id {
            pyksnp::stream::stream_id sid{};
            std::ranges::copy(self.stream_id, sid.begin());
            return sid;
        });

    nb::class_<ksnp_server_event_new_capacity>(mod, "NewCapacity")
        .def_ro("additional_capacity", &ksnp_server_event_new_capacity::additional_capacity)
        .def_ro("current_capacity", &ksnp_server_event_new_capacity::current_capacity);

    nb::class_<event::server_event_error>(mod, "Error")
        .def_ro("code", &event::server_event_error::code)
        .def_ro("description", &event::server_event_error::description)
        .def_prop_ro("stream", &event::server_event_error::get_stream);
}

}  // namespace event

using pyksnp::stream::stream;

class server
    : private pyksnp::serde::message_context
    , public ksnp::server
{
private:
    bool has_stream;

public:
    server() : ksnp::server(this->get_context()), has_stream(false)
    {}

    server(nb::bytearray read_buffer, nb::bytearray write_buffer)
        : pyksnp::serde::message_context(std::move(read_buffer), std::move(write_buffer))
        , ksnp::server(this->get_context())
        , has_stream(false)
    {}

    server(pyksnp::serde::buffer &read_buffer, pyksnp::serde::buffer &write_buffer)
        : pyksnp::serde::message_context(read_buffer, write_buffer)
        , ksnp::server(this->get_context())
        , has_stream(false)
    {}

    server(server const &) = delete;
    server(server &&)      = delete;

    ~server()
    {
        if (has_stream) {
            this->close_stream();
        }
    }

    auto operator=(server const &) -> server & = delete;
    auto operator=(server &&) -> server &      = delete;

    using ksnp::server::want_read;
    using ksnp::server::want_write;

    auto read_data(nb::memoryview const &buffer) -> size_t
    {
        pyksnp::pybuffer<false> view(buffer);
        return ksnp::server::read_data(view);
    }

    auto write_data(nb::memoryview const &buffer) -> size_t
    {
        pyksnp::pybuffer<true> view(buffer);
        return ksnp::server::write_data(view);
    }

    auto next_event() -> std::optional<event::server_event>
    {
        auto evt = ksnp::server::next_event();
        if (evt) {
            std::visit(overloads{
                           [this](ksnp_server_event_close_stream & /*evt*/) -> void {
                               this->has_stream = false;
                           },
                           [this](ksnp_server_event_error & /*evt*/) -> void {
                               this->has_stream = false;
                           },
                           [](auto && /*evt*/) -> void {},
                       },
                       *evt);
            return event::convert(*evt);
        }

        return std::nullopt;
    }

    auto open_stream_ok(stream *stream, pyksnp::stream::accepted_params const &parameters) -> void
    {
        this->has_stream = true;
        stream->inc_ref();
        auto raw_params = parameters.as_struct();
        ksnp::server::open_stream_ok(stream->as_stream_ptr(), &raw_params);
    }

    auto open_stream_fail(ksnp_status_code                          reason,
                          std::optional<pyksnp::stream::qos_params> parameters,
                          std::optional<char const *>               message) -> void
    {
        if (parameters) {
            auto raw_params = parameters->as_struct();
            ksnp::server::open_stream_fail(reason, &raw_params, message.value_or(nullptr));
        } else {
            ksnp::server::open_stream_fail(reason, nullptr, message.value_or(nullptr));
        }
    }

    auto suspend_stream_ok(uint32_t timeout) -> nb::ref<stream>
    {
        struct ksnp_stream *base_stream = ksnp::server::suspend_stream_ok(timeout);
        auto                stream_ref  = nb::ref<stream>(stream::from_stream_ptr(base_stream));
        stream_ref->dec_ref();
        this->has_stream = false;
        return stream_ref;
    }

    auto close_stream() -> nb::ref<stream>
    {
        struct ksnp_stream *base_stream = ksnp::server::close_stream();
        auto                stream_ref  = nb::ref<stream>(stream::from_stream_ptr(base_stream));
        stream_ref->dec_ref();
        this->has_stream = false;
        return stream_ref;
    }

    auto get_stream() -> nb::ref<stream>
    {
        struct ksnp_stream *base_stream = ksnp::server::get_stream();
        if (base_stream == nullptr) {
            return {};
        }
        return {stream::from_stream_ptr(base_stream)};
    }
};

auto register_module(nb::module_ &mod) -> void
{
    using namespace nb::literals;

    nb::class_<server>(mod, "Server")
        .def(nb::init<>())
        .def(nb::init<nb::bytearray, nb::bytearray>(), "read_buffer"_a, "write_buffer"_a)
        .def(nb::init<pyksnp::serde::buffer &, pyksnp::serde::buffer &>(),
             "read_buffer"_a,
             "write_buffer"_a,
             nb::keep_alive<1, 2>(),
             nb::keep_alive<1, 3>())
        .def("want_read", &server::want_read)
        .def("want_write", &server::want_write)
        .def("read_data", &server::read_data, "data"_a)
        .def("write_data", &server::write_data, "data"_a)
        .def("flush_data", &server::flush_data)
        .def("next_event", &server::next_event)
        .def("get_stream", &server::get_stream)
        .def("open_stream_ok", &server::open_stream_ok, "stream"_a, "parameters"_a)
        .def("open_stream_fail",
             &server::open_stream_fail,
             "reason"_a,
             "parameters"_a,
             "message"_a.none() = std::nullopt)
        .def("suspend_stream_ok", &server::suspend_stream_ok, "timeout"_a)
        .def("suspend_stream_fail", &server::suspend_stream_fail, "reason"_a, "message"_a.none() = std::nullopt)
        .def("keep_alive_ok", &server::keep_alive_ok)
        .def("keep_alive_fail", &server::keep_alive_fail, "reason"_a, "message"_a.none() = std::nullopt)
        .def("close_stream", &server::close_stream)
        .def("close_connection", &server::close_connection, "dir"_a);
}

}  // namespace pyksnp::server
