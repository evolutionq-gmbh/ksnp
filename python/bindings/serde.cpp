#include <Python.h>

#include <ksnp/messages.h>
#include <ksnp/types.h>
#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/variant.h>

#include "serde.h"
#include "stream.h"

namespace pyksnp::serde
{

namespace messages
{

using namespace nb::literals;

auto register_module(nb::module_ &mod) -> void
{
    nb::class_<ksnp_msg_error>(mod, "Error")
        .def(nb::init<ksnp_error_code>(), "code"_a)
        .def_ro("code", &ksnp_msg_error::code);

    nb::class_<ksnp_msg_version>(mod, "Version")
        .def(nb::init<ksnp_protocol_version, ksnp_protocol_version>(), "minimum_version"_a, "maximum_version"_a)
        .def_ro("minimum_version", &ksnp_msg_version::minimum_version)
        .def_ro("maximum_version", &ksnp_msg_version::maximum_version);

    nb::class_<open_stream>(mod, "OpenStream")
        .def(nb::init<pyksnp::stream::open_params>(), "parameters"_a)
        .def_ro("parameters", &open_stream::parameters);

    nb::class_<open_stream_reply>(mod, "OpenStreamReply")
        .def(nb::init<ksnp_status_code,
                      std::optional<std::variant<pyksnp::stream::accepted_params, pyksnp::stream::qos_params>>,
                      nb::str>(),
             "code"_a,
             "parameters"_a,
             "message"_a)
        .def_ro("code", &open_stream_reply::code)
        .def_ro("parameters", &open_stream_reply::parameters)
        .def_ro("message", &open_stream_reply::message);

    (void)nb::class_<ksnp_msg_close_stream>(mod, "CloseStream").def(nb::init<>());

    (void)nb::class_<ksnp_msg_close_stream_reply>(mod, "CloseStreamReply").def(nb::init<>());

    nb::class_<close_stream_notify>(mod, "CloseStreamNotify")
        .def(nb::init<ksnp_status_code, nb::str>(), "code"_a, "message"_a)
        .def_ro("code", &close_stream_notify::code)
        .def_ro("message", &close_stream_notify::message);

    nb::class_<ksnp_msg_suspend_stream>(mod, "SuspendStream")
        .def(nb::init<std::uint32_t>(), "timeout"_a)
        .def_ro("timeout", &ksnp_msg_suspend_stream::timeout);

    nb::class_<suspend_stream_reply>(mod, "SuspendStreamReply")
        .def(nb::init<ksnp_status_code, std::uint32_t, nb::str>(), "code"_a, "timeout"_a, "message"_a)
        .def_ro("code", &suspend_stream_reply::code)
        .def_ro("timeout", &suspend_stream_reply::timeout)
        .def_ro("message", &suspend_stream_reply::message);

    nb::class_<ksnp_msg_suspend_stream_notify>(mod, "SuspendStreamNotify")
        .def(nb::init<ksnp_status_code, std::uint32_t>(), "code"_a, "timeout"_a)
        .def_ro("code", &ksnp_msg_suspend_stream_notify::code)
        .def_ro("timeout", &ksnp_msg_suspend_stream_notify::timeout);

    nb::class_<ksnp_msg_keep_alive_stream>(mod, "KeepAliveStream")
        .def(
            "__init__",
            [](ksnp_msg_keep_alive_stream *msg, stream::stream_id stream_id) -> void {
                new (msg) ksnp_msg_keep_alive_stream{};
                std::ranges::copy(stream_id, std::begin(msg->key_stream_id));
            },
            "stream_id"_a)
        .def_ro("key_stream_id", &ksnp_msg_keep_alive_stream::key_stream_id);

    nb::class_<keep_alive_stream_reply>(mod, "KeepAliveStreamReply")
        .def(nb::init<ksnp_status_code, nb::str>(), "code"_a, "message"_a)
        .def_ro("code", &keep_alive_stream_reply::code)
        .def_ro("message", &keep_alive_stream_reply::message);

    nb::class_<ksnp_msg_capacity_notify>(mod, "CapacityNotify")
        .def(nb::init<std::uint32_t>(), "additional_capacity"_a)
        .def_ro("additional_capacity", &ksnp_msg_capacity_notify::additional_capacity);

    nb::class_<key_data_notify>(mod, "KeyDataNotify")
        .def(nb::init<nb::bytes>(), "key_data"_a)
        .def_ro("key_data", &key_data_notify::key_data);
}
}  // namespace messages

using namespace nb::literals;

auto message_context::next_event() -> std::optional<message>
{
    auto msg = this->context.next_message();
    if (msg) {
        return std::visit(overloads{
                              [](ksnp_msg_open_stream msg) -> message {
                                  return messages::open_stream(msg);
                              },
                              [](ksnp_msg_open_stream_reply msg) -> message {
                                  return messages::open_stream_reply(msg);
                              },
                              [](ksnp_msg_close_stream_notify msg) -> message {
                                  return messages::close_stream_notify(msg);
                              },
                              [](ksnp_msg_suspend_stream_reply msg) -> message {
                                  return messages::suspend_stream_reply(msg);
                              },
                              [](ksnp_msg_keep_alive_stream_reply msg) -> message {
                                  return messages::keep_alive_stream_reply(msg);
                              },
                              [](ksnp_msg_key_data_notify msg) -> message {
                                  return messages::key_data_notify(msg);
                              },
                              [](auto &&msg) -> message {
                                  return msg;
                              },
                          },
                          *msg);
    }
    return std::nullopt;
}

auto message_context::write_message(message const &msg) -> void
{
    std::visit(overloads{
                   [this](messages::open_stream const &msg) -> void {
                       auto raw_params = msg.parameters.as_struct();
                       this->context.write_message(ksnp_msg_open_stream{.parameters = &raw_params});
                   },
                   [this](messages::open_stream_reply const &msg) -> void {
                       if (msg.parameters) {
                           std::visit(overloads{
                                          [this, &msg](stream::accepted_params const &params) -> void {
                                              auto raw_params = params.as_struct();
                                              this->context.write_message(
                                                  ksnp_msg_open_stream_reply{.code       = msg.code,
                                                                             .parameters = {.reply = &raw_params},
                                                                             .message    = msg.message.c_str()});
                                          },
                                          [this, &msg](stream::qos_params const &params) -> void {
                                              auto raw_params = params.as_struct();
                                              this->context.write_message(
                                                  ksnp_msg_open_stream_reply{.code       = msg.code,
                                                                             .parameters = {.qos = &raw_params},
                                                                             .message    = msg.message.c_str()});
                                          },
                                      },
                                      *msg.parameters);
                       } else {
                           this->context.write_message(ksnp_msg_open_stream_reply{
                               .code = msg.code, .parameters = {.qos = nullptr}, .message = msg.message.c_str()});
                       }
                   },
                   [this](messages::close_stream_notify const &msg) -> void {
                       this->context.write_message(
                           ksnp_msg_close_stream_notify{.code = msg.code, .message = msg.message.c_str()});
                   },
                   [this](messages::suspend_stream_reply const &msg) -> void {
                       this->context.write_message(ksnp_msg_suspend_stream_reply{
                           .code = msg.code, .timeout = msg.timeout, .message = msg.message.c_str()});
                   },
                   [this](messages::keep_alive_stream_reply const &msg) -> void {
                       this->context.write_message(
                           ksnp_msg_keep_alive_stream_reply{.code = msg.code, .message = msg.message.c_str()});
                   },
                   [this](messages::key_data_notify const &msg) -> void {
                       this->context.write_message(ksnp_msg_key_data_notify{
                           .key_data   = {.data = static_cast<unsigned char const *>(msg.key_data.data()),
                                          .len  = msg.key_data.size()},
                           .parameters = nullptr
                       });
                   },
                   [this](auto &&msg) -> void {
                       this->context.write_message(msg);
                   },
               },
               msg);
};

auto register_module(nb::module_ &mod) -> void
{
    nb::class_<buffer, buffer_trampoline>(
        mod, "Buffer", nb::intrusive_ptr<buffer>([](buffer *self, PyObject *py_obj) noexcept -> void {
            self->set_self_py(py_obj);
        }))
        .def(nb::init<>())
        .def("data", &buffer::contents_py)
        .def("consume", &buffer::consume_py, "count"_a)
        .def("append", &buffer::append_py, "data"_a)
        .def("truncate", &buffer::truncate_py, "size"_a);

    nb::class_<message_context>(mod, "MessageContext")
        .def(nb::init<>())
        .def(nb::init<nb::bytearray, nb::bytearray>(), "read_buffer"_a, "write_buffer"_a)
        .def(nb::init<buffer &, buffer &>(),
             "read_buffer"_a,
             "write_buffer"_a,
             nb::keep_alive<1, 2>(),
             nb::keep_alive<1, 3>())
        .def("want_read", &message_context::want_read)
        .def("want_write", &message_context::want_write)
        .def("read_data", &message_context::read_data, "data"_a)
        .def("write_data", &message_context::write_data, "data"_a)
        .def("next_event", &message_context::next_event)
        .def("write_message", &message_context::write_message, "msg"_a);
}

}  // namespace pyksnp::serde
