#include <Python.h>

#include <algorithm>
#include <utility>

#include <ksnp/types.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/tuple.h>
#include <nanobind/stl/variant.h>
#include <nanobind/stl/vector.h>

#include "ksnp.h"
#include "stream.h"

namespace pyksnp::stream
{

auto open_params::as_struct() const -> ksnp_stream_open_params
{
    ksnp_stream_open_params raw_params{};
    if (this->stream_id) {
        std::ranges::copy(*this->stream_id, std::begin(raw_params.stream_id));
    }
    raw_params.destination = this->destination.to_ksnp_address();
    if (this->source) {
        raw_params.source = this->source->to_ksnp_address();
    }
    raw_params.chunk_size = this->chunk_size;
    raw_params.capacity   = this->capacity;
    if (this->min_bps) {
        raw_params.min_bps = this->min_bps->to_ksnp_rate();
    }
    if (this->max_bps) {
        raw_params.max_bps = this->max_bps->to_ksnp_rate();
    }
    raw_params.ttl            = this->ttl;
    raw_params.provision_size = this->provision_size;

    return raw_params;
}

auto accepted_params::as_struct() const -> ksnp_stream_accepted_params
{
    ksnp_stream_accepted_params raw_params{};
    if (this->stream_id) {
        std::ranges::copy(*this->stream_id, std::begin(raw_params.stream_id));
    }
    raw_params.chunk_size    = this->chunk_size;
    raw_params.position      = this->position;
    raw_params.max_key_delay = this->max_key_delay;
    if (this->min_bps) {
        raw_params.min_bps = this->min_bps->to_ksnp_rate();
    }
    raw_params.provision_size = this->provision_size;
    return raw_params;
}

auto qos_params::as_struct() const -> ksnp_stream_qos_params
{
    ksnp_stream_qos_params raw_params{};
    raw_params.chunk_size     = this->chunk_size.to_ksnp_qos<ksnp_qos_u16>();
    raw_params.min_bps        = this->min_bps.to_ksnp_qos<ksnp_qos_rate>();
    raw_params.ttl            = this->ttl.to_ksnp_qos<ksnp_qos_u32>();
    raw_params.provision_size = this->provision_size.to_ksnp_qos<ksnp_qos_u32>();
    return raw_params;
}

auto register_module(nb::module_ &mod) -> void
{
    using namespace nb::literals;

    nb::class_<stream, stream_trampoline>(
        mod, "Stream", nb::intrusive_ptr<stream>([](stream *self, PyObject *py_obj) noexcept -> void {
            self->set_self_py(py_obj);
        }))
        .def(nb::init<uint16_t>(), "chunk_size"_a)
        .def_prop_ro("chunk_size", &stream::chunk_size)
        .def("next_chunk", &stream::next_chunk, "max_count"_a)
        .def("has_chunk_available", &stream::has_chunk_available);

    nb::class_<open_params>(mod, "OpenParams")
        .def(nb::init<address,
                      std::optional<stream_id>,
                      std::optional<address>,
                      std::uint16_t,
                      std::uint32_t,
                      std::optional<rate>,
                      std::optional<rate>,
                      std::uint32_t,
                      std::uint32_t>(),
             "destination"_a,
             "stream_id"_a.none() = std::nullopt,
             "source"_a.none()    = std::nullopt,
             "chunk_size"_a       = 0,
             "capacity"_a         = 0,
             "min_bps"_a.none()   = std::nullopt,
             "max_bps"_a.none()   = std::nullopt,
             "ttl"_a              = 0,
             "provision_size"_a   = 0)
        .def_ro("stream_id", &open_params::stream_id)
        .def_ro("source", &open_params::source)
        .def_ro("destination", &open_params::destination)
        .def_ro("chunk_size", &open_params::chunk_size)
        .def_ro("capacity", &open_params::capacity)
        .def_ro("min_bps", &open_params::min_bps)
        .def_ro("max_bps", &open_params::max_bps)
        .def_ro("ttl", &open_params::ttl)
        .def_ro("provision_size", &open_params::provision_size);

    nb::class_<accepted_params>(mod, "AcceptedParams")
        .def(nb::init<std::optional<stream_id>,
                      std::uint16_t,
                      std::uint32_t,
                      std::uint32_t,
                      std::optional<rate>,
                      std::uint32_t>(),
             "stream_id"_a.none() = std::nullopt,
             "chunk_size"_a       = 0,
             "position"_a         = 0,
             "max_key_delay"_a    = 0,
             "min_bps"_a.none()   = std::nullopt,
             "provision_size"_a   = 0)
        .def_ro("stream_id", &accepted_params::stream_id)
        .def_ro("chunk_size", &accepted_params::chunk_size)
        .def_ro("position", &accepted_params::position)
        .def_ro("max_key_delay", &accepted_params::max_key_delay)
        .def_ro("min_bps", &accepted_params::min_bps)
        .def_ro("provision_size", &accepted_params::provision_size);

    nb::class_<qos_params>(mod, "QosParams")
        .def(
            "__init__",
            [](qos_params   *params,
               qos<uint16_t> chunk_size,
               qos<rate>     min_bps,
               qos<uint32_t> ttl,
               qos<uint32_t> provision_size) -> void {
                new (params) qos_params(std::move(chunk_size),
                                        qos<rate>::convert_value<ksnp_rate>(std::move(min_bps)),
                                        std::move(ttl),
                                        std::move(provision_size));
            },
            "chunk_size"_a.none()     = std::nullopt,
            "min_bps"_a.none()        = std::nullopt,
            "ttl"_a.none()            = std::nullopt,
            "provision_size"_a.none() = std::nullopt)
        .def_ro("chunk_size", &qos_params::chunk_size)
        .def_prop_ro("min_bps",
                     [](qos_params const &params) -> qos<rate> {
                         return qos<ksnp_rate>::convert_value<rate>(params.min_bps);
                     })
        .def_ro("ttl", &qos_params::ttl)
        .def_ro("provision_size", &qos_params::provision_size);
}
}  // namespace pyksnp::stream
