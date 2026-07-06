#include <Python.h>

#include <ksnp/types.h>
#include <ksnp/types.hpp>
#include <nanobind/intrusive/counter.inl>
#include <nanobind/nanobind.h>

#include "ksnp.h"

namespace nb = nanobind;

// NOLINTNEXTLINE
NB_MODULE(_core, mod)
{
    // Sometimes daemon threads do not release handles properly when stopped,
    // triggering leak warnings. This is not something that can be fixed without
    // modifying nanobind or Python. Turn leak warnings off, the user cannot do
    // anything with them anyway.
    nb::set_leak_warnings(false);

    nb::intrusive_init(
        [](PyObject *py_obj) noexcept -> void {
            nb::gil_scoped_acquire guard;
            // NOLINTNEXTLINE
            Py_INCREF(py_obj);
        },
        [](PyObject *py_obj) noexcept -> void {
            nb::gil_scoped_acquire guard;
            // NOLINTNEXTLINE
            Py_DECREF(py_obj);
        });

    nb::enum_<ksnp_error>(mod, "Error")
        .value("NO_ERROR", ksnp_error::KSNP_E_NO_ERROR)
        .value("UNKNOWN", ksnp_error::KSNP_E_UNKNOWN)
        .value("NO_MEM", ksnp_error::KSNP_E_NO_MEM)
        .value("PROTOCOL_ERROR", ksnp_error::KSNP_E_PROTOCOL_ERROR)
        .value("SER_MSG_TOO_LARGE", ksnp_error::KSNP_E_SER_MSG_TOO_LARGE)
        .value("SER_JSON_TOO_LARGE", ksnp_error::KSNP_E_SER_JSON_TOO_LARGE)
        .value("UNSUPPORTED_VERSION", ksnp_error::KSNP_E_UNSUPPORTED_VERSION)
        .value("INVALID_OPERATION", ksnp_error::KSNP_E_INVALID_OPERATION)
        .value("INVALID_ARGUMENT", ksnp_error::KSNP_E_INVALID_ARGUMENT)
        .value("KEY_DATA_TOO_LARGE", ksnp_error::KSNP_E_KEY_DATA_TOO_LARGE)
        .value("KEY_DATA_NOT_CHUNKED", ksnp_error::KSNP_E_KEY_DATA_NOT_CHUNKED)
        .value("CHUNK_SIZE_TOO_LARGE", ksnp_error::KSNP_E_CHUNK_SIZE_TOO_LARGE)
        .value("INVALID_MESSAGE_TYPE", ksnp_error::KSNP_E_INVALID_MESSAGE_TYPE)
        .value("INVALID_EVENT_TYPE", ksnp_error::KSNP_E_INVALID_EVENT_TYPE)
        .value("INSUFFICIENT_BUFFER", ksnp_error::KSNP_E_INSUFFICIENT_BUFFER)
        .def("__str__", ksnp_error_description);

    nb::enum_<ksnp_error_code>(mod, "ProtocolError")
        .value("UNKNOWN_ERROR", ksnp_error_code::KSNP_PROT_E_UNKNOWN_ERROR)
        .value("UNEXPECTED_MESSAGE", ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE)
        .value("EXCESSIVE_CAPACITY", ksnp_error_code::KSNP_PROT_E_EXCESSIVE_CAPACITY)
        .value("INVALID_CHUNK", ksnp_error_code::KSNP_PROT_E_INVALID_CHUNK)
        .value("TIMEOUT", ksnp_error_code::KSNP_PROT_E_TIMEOUT)
        .value("BAD_MSG_TYPE", ksnp_error_code::KSNP_PROT_E_BAD_MSG_TYPE)
        .value("BAD_MSG_LENGTH", ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH)
        .value("JSON_MISSING", ksnp_error_code::KSNP_PROT_E_JSON_MISSING)
        .value("BAD_JSON", ksnp_error_code::KSNP_PROT_E_BAD_JSON)
        .value("BAD_JSON_TYPE", ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE)
        .value("BAD_JSON_LENGTH", ksnp_error_code::KSNP_PROT_E_BAD_JSON_LENGTH)
        .value("JSON_KEY_MISSING", ksnp_error_code::KSNP_PROT_E_JSON_KEY_MISSING)
        .value("BAD_JSON_KEY", ksnp_error_code::KSNP_PROT_E_BAD_JSON_KEY)
        .value("BAD_JSON_VAL", ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL)
        .value("INCOMPLETE_MSG", ksnp_error_code::KSNP_PROT_E_INCOMPLETE_MSG)
        .def("__str__", ksnp_protocol_error_description);

    nb::enum_<ksnp_status_code>(mod, "StatusCode")
        .value("SUCCESS", ksnp_status_code::KSNP_STATUS_SUCCESS)
        .value("INVALID_PARAMETER", ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER)
        .value("OPERATION_NOT_SUPPORTED", ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED)
        .value("NOTIFY_DUE_TO_PEER", ksnp_status_code::KSNP_STATUS_NOTIFY_DUE_TO_PEER)
        .value("INSUFFICIENT_RESOURCES", ksnp_status_code::KSNP_STATUS_INSUFFICIENT_RESOURCES)
        .value("UNSUPPORTED_EXTENSION", ksnp_status_code::KSNP_STATUS_UNSUPPORTED_EXTENSION)
        .value("MALFORMED_EXTENSION", ksnp_status_code::KSNP_STATUS_MALFORMED_EXTENSION)
        .value("TIMEOUT", ksnp_status_code::KSNP_STATUS_TIMEOUT)
        .value("STREAM_IN_USE", ksnp_status_code::KSNP_STATUS_STREAM_IN_USE)
        .value("UNAUTHENTICATED", ksnp_status_code::KSNP_STATUS_UNAUTHENTICATED)
        .value("UNAUTHORIZED", ksnp_status_code::KSNP_STATUS_UNAUTHORIZED)
        .value("QOS_OUT_OF_RANGE", ksnp_status_code::KSNP_STATUS_QOS_OUT_OF_RANGE)
        .value("QOS_UNSATISFIABLE", ksnp_status_code::KSNP_STATUS_QOS_UNSATISFIABLE)
        .value("DESTINATION_UNKNOWN", ksnp_status_code::KSNP_STATUS_DESTINATION_UNKNOWN)
        .value("DESTINATION_UNAVAILABLE", ksnp_status_code::KSNP_STATUS_DESTINATION_UNAVAILABLE)
        .value("STREAM_CLOSED", ksnp_status_code::KSNP_STATUS_STREAM_CLOSED)
        .def("__str__", ksnp_status_code_description);

    nb::enum_<ksnp_protocol_version>(mod, "ProtocolVersion").value("V1", ksnp_protocol_version::PROTOCOL_V1);

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    (void)nb::exception<ksnp::exception>(mod, "Exception", PyExc_RuntimeError);
    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    (void)nb::exception<ksnp::protocol_exception>(mod, "ProtocolException", PyExc_RuntimeError);
    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    (void)nb::exception<ksnp::version_exception>(mod, "VersionException", PyExc_RuntimeError);

    nb::enum_<ksnp_close_direction>(mod, "CloseDirection")
        .value("READ", ksnp_close_direction::KSNP_CLOSE_READ)
        .value("WRITE", ksnp_close_direction::KSNP_CLOSE_WRITE)
        .value("BOTH", ksnp_close_direction::KSNP_CLOSE_BOTH);

    nb::module_ mod_stream = mod.def_submodule("stream", "Stream definitions");
    pyksnp::stream::register_module(mod_stream);

    nb::module_ mod_serde = mod.def_submodule("serde", "Message serialization and deserialization");
    pyksnp::serde::register_module(mod_serde);

    nb::module_ mod_messages = mod_serde.def_submodule("messages", "Protocol message definitions");
    pyksnp::serde::messages::register_module(mod_messages);

    nb::module_ mod_client = mod.def_submodule("client", "KSNP client definitions");
    pyksnp::client::register_module(mod_client);
    nb::module_ mod_client_event = mod_client.def_submodule("event", "Client events");
    pyksnp::client::event::register_module(mod_client_event);

    nb::module_ mod_server = mod.def_submodule("server", "KSNP server definitions");
    pyksnp::server::register_module(mod_server);
    nb::module_ mod_server_event = mod_server.def_submodule("event", "Server events");
    pyksnp::server::event::register_module(mod_server_event);
}
