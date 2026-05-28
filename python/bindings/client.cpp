#include <Python.h>

#include <optional>
#include <utility>
#include <variant>

#include <ksnp/client.hpp>
#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/variant.h>

#include "ksnp.h"
#include "serde.h"
#include "stream.h"

namespace pyksnp::client
{

namespace nb = nanobind;

namespace event
{

class stream_accepted
{
public:
    pyksnp::stream::accepted_params parameters;

    explicit stream_accepted(ksnp_client_event_stream_open event) : parameters(event.parameters.reply)
    {}
};

class stream_rejected
{
public:
    ksnp_status_code                          code;
    std::optional<pyksnp::stream::qos_params> parameters;
    nb::str                                   message;

    explicit stream_rejected(ksnp_client_event_stream_open event)
        : code(event.code)
        , message((event.message != nullptr) ? event.message : "")
    {
        if (event.parameters.qos != nullptr) {
            parameters = pyksnp::stream::qos_params(event.parameters.qos);
        }
    }
};

class stream_close
{
public:
    ksnp_status_code code;
    nb::str          message;

    explicit stream_close(ksnp_client_event_stream_close event)
        : code(event.code)
        , message((event.message != nullptr) ? event.message : "")
    {}
};

class stream_suspend
{
public:
    ksnp_status_code code;
    std::uint32_t    timeout;
    nb::str          message;

    explicit stream_suspend(ksnp_client_event_stream_suspend event)
        : code(event.code)
        , timeout(event.timeout)
        , message((event.message != nullptr) ? event.message : "")
    {}
};

class key_data
{
public:
    nb::bytes data;

    explicit key_data(ksnp_client_event_key_data event) : data(event.key_data.data, event.key_data.len)
    {}
};

class keep_alive
{
public:
    ksnp_status_code code;
    nb::str          message;

    explicit keep_alive(ksnp_client_event_keep_alive event)
        : code(event.code)
        , message((event.message != nullptr) ? event.message : "")
    {}
};

class event_error
{
public:
    ksnp_error_code code;
    nb::str         description;

    explicit event_error(ksnp_client_event_error event)
        : code(event.code)
        , description((event.description != nullptr) ? event.description : "")
    {}
};

using client_event = std::variant<ksnp_client_event_handshake,
                                  stream_accepted,
                                  stream_rejected,
                                  stream_close,
                                  stream_suspend,
                                  key_data,
                                  keep_alive,
                                  event_error>;

namespace
{
auto convert(ksnp::client_event event) -> client_event
{
    auto const visitor = overloads{
        [](ksnp_client_event_handshake evt) -> client_event {
            return evt;
        },
        [](ksnp_client_event_stream_open evt) -> client_event {
            if (evt.code != ksnp_status_code::KSNP_STATUS_SUCCESS) {
                return stream_rejected(evt);
            }
            return stream_accepted(evt);
        },
        [](ksnp_client_event_stream_close evt) -> client_event {
            return stream_close(evt);
        },
        [](ksnp_client_event_stream_suspend evt) -> client_event {
            return stream_suspend(evt);
        },
        [](ksnp_client_event_key_data evt) -> client_event {
            return key_data(evt);
        },
        [](ksnp_client_event_keep_alive evt) -> client_event {
            return keep_alive(evt);
        },
        [](ksnp_client_event_error evt) -> client_event {
            return event_error(evt);
        },
    };
    return std::visit(visitor, event);
}

}  // namespace

auto register_module(nb::module_ &mod) -> void
{
    nb::class_<ksnp_client_event_handshake>(mod, "Handshake")
        .def_ro("protocol", &ksnp_client_event_handshake::protocol);

    (void)nb::class_<client::event::stream_accepted>(mod, "StreamAccepted")
        .def_ro("parameters", &client::event::stream_accepted::parameters);

    (void)nb::class_<client::event::stream_rejected>(mod, "StreamRejected")
        .def_ro("code", &client::event::stream_rejected::code)
        .def_ro("parameters", &client::event::stream_rejected::parameters)
        .def_ro("message", &client::event::stream_rejected::message);

    (void)nb::class_<client::event::stream_close>(mod, "StreamClose")
        .def_ro("code", &client::event::stream_close::code)
        .def_ro("message", &client::event::stream_close::message);

    (void)nb::class_<client::event::stream_suspend>(mod, "StreamSuspend")
        .def_ro("code", &client::event::stream_suspend::code)
        .def_ro("timeout", &client::event::stream_suspend::timeout)
        .def_ro("message", &client::event::stream_suspend::message);

    (void)nb::class_<client::event::key_data>(mod, "KeyData").def_ro("key_data", &event::key_data::data);

    (void)nb::class_<client::event::keep_alive>(mod, "KeepAlive")
        .def_ro("code", &client::event::keep_alive::code)
        .def_ro("message", &client::event::keep_alive::message);

    (void)nb::class_<client::event::event_error>(mod, "Error")
        .def_ro("code", &client::event::event_error::code)
        .def_ro("description", &client::event::event_error::description);
}

}  // namespace event

class client
    : private pyksnp::serde::message_context
    , public ksnp::client
{
public:
    client() : ksnp::client(this->get_context())
    {}

    client(nb::bytearray read_buffer, nb::bytearray write_buffer)
        : pyksnp::serde::message_context(std::move(read_buffer), std::move(write_buffer))
        , ksnp::client(this->get_context())
    {}

    client(pyksnp::serde::buffer &read_buffer, pyksnp::serde::buffer &write_buffer)
        : pyksnp::serde::message_context(read_buffer, write_buffer)
        , ksnp::client(this->get_context())
    {}

    using ksnp::client::want_read;
    using ksnp::client::want_write;

    auto read_data(nb::memoryview const &buffer) -> size_t
    {
        pyksnp::pybuffer<false> view(buffer);
        return ksnp::client::read_data({view});
    }

    auto write_data(nb::memoryview const &buffer) -> size_t
    {
        pyksnp::pybuffer<true> view(buffer);
        return ksnp::client::write_data({view});
    }

    auto next_event() -> std::optional<event::client_event>
    {
        auto evt = ksnp::client::next_event();
        if (evt) {
            return event::convert(*evt);
        }

        return std::nullopt;
    }

    auto open_stream(pyksnp::stream::open_params const &params) -> void
    {
        auto raw_params = params.as_struct();
        ksnp::client::open_stream(&raw_params);
    }
};

auto register_module(nb::module_ &mod) -> void
{
    using namespace nb::literals;

    nb::class_<client>(mod, "Client")
        .def(nb::init<>())
        .def(nb::init<nb::bytearray, nb::bytearray>(), "read_buffer"_a, "write_buffer"_a)
        .def(nb::init<pyksnp::serde::buffer &, pyksnp::serde::buffer &>(),
             "read_buffer"_a,
             "write_buffer"_a,
             nb::keep_alive<1, 2>(),
             nb::keep_alive<1, 3>())
        .def("want_read", &client::want_read)
        .def("want_write", &client::want_write)
        .def("read_data", &client::read_data, "data"_a)
        .def("write_data", &client::write_data, "data"_a)
        .def("flush_data", &client::flush_data)
        .def("next_event", &client::next_event)
        .def("open_stream", &client::open_stream, "parameters"_a)
        .def("add_capacity", &client::add_capacity, "additional_capacity"_a)
        .def("close_stream", &client::close_stream)
        .def("close_connection", &client::close_connection, "dir"_a);
}

}  // namespace pyksnp::client
