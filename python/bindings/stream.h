#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <span>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <ksnp/server.h>
#include <ksnp/types.h>
#include <ksnp/types.hpp>
#include <nanobind/intrusive/counter.h>
#include <nanobind/nanobind.h>
#include <nanobind/trampoline.h>

#include "ksnp.h"

namespace pyksnp::stream
{

namespace nb = nanobind;

/**
 * @brief Stream ID wrapper.
 *
 * This type has an associated type caster that allows it to be converted to and
 * from the python uuid.UUID type.
 */
struct stream_id : public std::array<unsigned char, sizeof(ksnp_key_stream_id)> {};

/**
 * @brief Base class for key streams.
 *
 * Python classes may inherit from this type to create concrete key streams that
 * are accepted by the server type.
 *
 * The default implementation for all methods always acts as if the stream is
 * empty.
 */
class stream
    : public nb::intrusive_base
    , protected ksnp_stream
{
private:
    // Storage for the memoryview that tracks the last provided key bytes to the
    // KSNP library.
    mutable std::optional<pybuffer<false>> last_view;

public:
    explicit stream(uint16_t chunk_size)
        : ksnp_stream{.chunk_size          = chunk_size,
                      .has_chunk_available = has_chunk_available_fn,
                      .next_chunk          = next_chunk_fn,
                      .user_data           = this}
    {}

    stream(stream const &) = delete;

    stream(stream &&other) noexcept : ksnp_stream(other)
    {
        this->user_data = this;  // NOLINT(cppcoreguidelines-prefer-member-initializer)
    }

    ~stream() override = default;

    auto operator=(stream const &) -> stream & = delete;

    auto operator=(stream &&other) noexcept -> stream &
    {
        static_cast<ksnp_stream &>(*this) = static_cast<ksnp_stream &>(other);
        this->user_data                   = this;
        return *this;
    }

    static auto from_stream_ptr(ksnp_stream *base_stream) -> stream *
    {
        return static_cast<stream *>(base_stream->user_data);
    }

    static auto from_stream_ptr(ksnp_stream const *base_stream) -> stream const *
    {
        return static_cast<stream const *>(base_stream->user_data);
    }

    auto as_stream_ptr() -> ksnp_stream *
    {
        return this;
    }

    [[nodiscard]] auto chunk_size() const -> uint16_t
    {
        return ksnp_stream::chunk_size;
    }

    [[nodiscard]] virtual auto has_chunk_available() const noexcept -> bool
    {
        return false;
    }

    [[nodiscard]] virtual auto next_chunk(uint16_t /*max_count*/) const -> nb::memoryview
    {
        return nb::memoryview{nb::bytes("")};
    }

private:
    static auto has_chunk_available_fn(ksnp_stream const *base_stream) noexcept -> bool
    {
        return from_stream_ptr(base_stream)->has_chunk_available();
    }

    static auto next_chunk_fn(ksnp_stream *base_stream, ksnp_cdata *chunk_data, uint16_t max_count) noexcept
        -> ksnp_error
    try {
        auto *self = from_stream_ptr(base_stream);

        auto bytes = self->next_chunk(max_count);
        self->last_view.emplace(bytes);
        chunk_data->data = self->last_view->data();
        chunk_data->len  = self->last_view->size();

        return ksnp_error::KSNP_E_NO_ERROR;
    } catch (ksnp::exception const &e) {
        return e.code();
    } catch (nb::python_error &e) {
        e.discard_as_unraisable(__func__);
        return ksnp_error::KSNP_E_UNKNOWN;
    } catch (std::bad_alloc const &) {
        return ksnp_error::KSNP_E_NO_MEM;
    } catch (...) {
        return ksnp_error::KSNP_E_UNKNOWN;
    }
};

/**
 * @brief Trampoline class for nanobind to handle virtual function dispatching.
 */
class stream_trampoline : stream
{
    NB_TRAMPOLINE(stream, 2);

public:
    explicit stream_trampoline(uint16_t chunk_size) : stream(chunk_size)
    {}

    [[nodiscard]] auto has_chunk_available() const noexcept -> bool override
    {
        // NOLINTNEXTLINE
        NB_OVERRIDE(has_chunk_available);
    }

    auto next_chunk(uint16_t max_count) const -> nb::memoryview override
    {
        // NOLINTNEXTLINE
        NB_OVERRIDE(next_chunk, max_count);
    }
};

/**
 * @brief Wrapper for KSNP addresses.
 *
 * This type enables type casting using basic Python types.
 */
class address : public std::variant<nb::str, std::tuple<nb::str, nb::str>>
{
public:
    using base = std::variant<nb::str, std::tuple<nb::str, nb::str>>;

    using base::base;
    using base::operator=;

    explicit address(base value) : base(std::move(value))
    {}

    explicit address(ksnp_address address)
    {
        if (address.network != nullptr) {
            base::operator=(std::make_tuple(nb::str(address.sae), nb::str(address.network)));
        }

        base::operator=(nb::str(address.sae));
    }

    [[nodiscard]] auto to_ksnp_address() const -> ksnp_address
    {
        return std::visit(
            [](auto &&arg) -> ksnp_address {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, nb::str>) {
                    return ksnp_address{.sae = arg.c_str(), .network = nullptr};
                } else if constexpr (std::is_same_v<T, std::tuple<nb::str, nb::str>>) {
                    return ksnp_address{.sae = std::get<0>(arg).c_str(), .network = std::get<1>(arg).c_str()};
                }
            },
            *this);
    }
};

/**
 * @brief Wrapper for KSNP stream rates.
 *
 * This type enables type casting using basic Python types.
 */
class rate : public std::variant<uint32_t, std::tuple<uint32_t, uint32_t>>
{
public:
    using base = std::variant<uint32_t, std::tuple<uint32_t, uint32_t>>;

    using base::base;
    using base::operator=;

    explicit rate(base value) : base(std::move(value))
    {}

    explicit rate(ksnp_rate rate)
    {
        if (rate.seconds != 0) {
            base::operator=(std::make_tuple(rate.bits, rate.seconds));
        }

        base::operator=(rate.bits);
    }

    [[nodiscard]] auto to_ksnp_rate() const -> ksnp_rate
    {
        return std::visit(
            [](auto &&arg) -> ksnp_rate {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, uint32_t>) {
                    if (arg == 0) {
                        throw nb::value_error("zero rate");
                    }
                    return ksnp_rate{.bits = arg, .seconds = 0};
                } else if constexpr (std::is_same_v<T, std::tuple<uint32_t, uint32_t>>) {
                    if (std::get<0>(arg) == 0) {
                        throw nb::value_error("zero rate");
                    }
                    return ksnp_rate{.bits = std::get<0>(arg), .seconds = std::get<1>(arg)};
                }
            },
            *this);
    }
};

namespace qos_detail
{
template<typename X, typename Y>
auto inline convert(Y val) -> X
{
    return X(val);
}

template<>
auto inline convert<ksnp_rate, rate>(rate val) -> ksnp_rate
{
    return val.to_ksnp_rate();
}
}  // namespace qos_detail

/**
 * @brief Wrapper for KSNP QoS values.
 *
 * This type enables type casting using basic Python types.
 */
template<typename T>
class qos : public std::optional<std::variant<std::monostate, std::tuple<T, T>, std::vector<T>>>
{
public:
    using base = std::optional<std::variant<std::monostate, std::tuple<T, T>, std::vector<T>>>;

    using base::base;
    using base::operator=;

    explicit qos(base value) : base(value)
    {}

    template<typename Value>
    explicit qos(Value ksnp_qos)
    {
        switch (ksnp_qos.type) {
        default:
        case ksnp_qos_type::KSNP_QOS_NONE:
            base::operator=(std::nullopt);
            break;
        case ksnp_qos_type::KSNP_QOS_NULL:
            base::operator=(std::monostate{});
            break;
        case ksnp_qos_type::KSNP_QOS_RANGE:
            base::operator=(std::make_tuple(qos_detail::convert<T>(ksnp_qos.range.min),
                                            qos_detail::convert<T>(ksnp_qos.range.max)));
            break;
        case ksnp_qos_type::KSNP_QOS_LIST: {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
            std::span qos_items(ksnp_qos.list.values, ksnp_qos.list.count);
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
            std::vector<T> list;
            list.reserve(qos_items.size());
            for (auto const &item: qos_items) {
                list.push_back(qos_detail::convert<T>(item));
            }
            base::operator=(list);
            break;
        }
        }
    }

    template<typename U>
    [[nodiscard]] auto to_ksnp_qos() const -> U
    {
        if (!this->has_value()) {
            return U{.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0};
        }
        return std::visit(overloads{
                              [](std::monostate /*arg*/) -> U {
                                  return U{.type = ksnp_qos_type::KSNP_QOS_NULL, .none = 0};
                              },
                              [](std::tuple<T, T> arg) -> U {
                                  return U{
                                      .type  = ksnp_qos_type::KSNP_QOS_RANGE,
                                      .range = {.min = std::get<0>(arg), .max = std::get<1>(arg)}
                                  };
                              },
                              [](std::vector<T> arg) -> U {
                                  return U{
                                      .type = ksnp_qos_type::KSNP_QOS_LIST,
                                      .list = {.values = arg.data(), .count = arg.size()}
                                  };
                              },
                          },
                          this->value());
    }

    template<typename U>
    [[nodiscard]] static auto convert_value(qos<T> qos_val) -> qos<U>
    {
        if (!qos_val) {
            return std::nullopt;
        }
        return std::visit(overloads{
                              [](std::monostate /*arg*/) -> qos<U> {
                                  return std::monostate{};
                              },
                              [](std::tuple<T, T> arg) -> qos<U> {
                                  return std::make_tuple(qos_detail::convert<U>(std::get<0>(arg)),
                                                         qos_detail::convert<U>(std::get<1>(arg)));
                              },
                              [](std::vector<T> const &arg) -> qos<U> {
                                  std::vector<U> result;
                                  result.reserve(arg.size());
                                  for (auto const &item: arg) {
                                      result.push_back(qos_detail::convert<U>(item));
                                  }

                                  return result;
                              },
                          },
                          *qos_val);
    }
};

class open_params
{
public:
    std::optional<struct stream_id> stream_id;
    std::optional<address>          source;
    address                         destination;
    uint16_t                        chunk_size;
    uint32_t                        capacity;
    std::optional<rate>             min_bps;
    std::optional<rate>             max_bps;
    uint32_t                        ttl;
    uint32_t                        provision_size;

    open_params(address                         destination,
                std::optional<struct stream_id> stream_id,
                std::optional<address>          source,
                uint16_t                        chunk_size,
                uint32_t                        capacity,
                std::optional<rate>             min_bps,
                std::optional<rate>             max_bps,
                uint32_t                        ttl,
                uint32_t                        provision_size)
        : stream_id(stream_id)
        , source(std::move(source))
        , destination(std::move(destination))
        , chunk_size(chunk_size)
        , capacity(capacity)
        , min_bps(std::move(min_bps))
        , max_bps(std::move(max_bps))
        , ttl(ttl)
        , provision_size(provision_size)

    {}

    explicit open_params(ksnp_stream_open_params const *parameters)
        : destination(parameters->destination)
        , chunk_size(parameters->chunk_size)
        , capacity(parameters->capacity)
        , ttl(parameters->ttl)
        , provision_size(parameters->provision_size)

    {
        if (uuid_is_null(std::begin(parameters->stream_id)) == 0) {
            struct stream_id sid{};
            std::ranges::copy(parameters->stream_id, sid.begin());
            this->stream_id = sid;
        }
        if (parameters->source.sae != nullptr) {
            this->source = address(parameters->source);
        }
        if (parameters->min_bps.bits != 0) {
            this->min_bps = rate(parameters->min_bps);
        }
        if (parameters->max_bps.bits != 0) {
            this->max_bps = rate(parameters->max_bps);
        }
    }

    [[nodiscard]] auto as_struct() const -> ksnp_stream_open_params;
};

class accepted_params
{
public:
    std::optional<struct stream_id> stream_id;
    uint16_t                        chunk_size;
    uint32_t                        position;
    uint32_t                        max_key_delay;
    std::optional<rate>             min_bps;
    uint32_t                        provision_size;

    accepted_params(std::optional<struct stream_id> stream_id,
                    uint16_t                        chunk_size,
                    uint32_t                        position,
                    uint32_t                        max_key_delay,
                    std::optional<rate>             min_bps,
                    uint32_t                        provision_size)
        : stream_id(stream_id)
        , chunk_size(chunk_size)
        , position(position)
        , max_key_delay(max_key_delay)
        , min_bps(std::move(min_bps))
        , provision_size(provision_size)

    {}

    explicit accepted_params(ksnp_stream_accepted_params const *parameters)
        : chunk_size(parameters->chunk_size)
        , position(parameters->position)
        , max_key_delay(parameters->max_key_delay)
        , provision_size(parameters->provision_size)

    {
        if (uuid_is_null(std::begin(parameters->stream_id)) == 0) {
            struct stream_id sid{};
            std::ranges::copy(parameters->stream_id, sid.begin());
            this->stream_id = sid;
        }
        if (parameters->min_bps.bits != 0) {
            this->min_bps = rate(parameters->min_bps);
        }
    }

    [[nodiscard]] auto as_struct() const -> ksnp_stream_accepted_params;
};

class qos_params
{
public:
    qos<uint16_t>  chunk_size;
    qos<ksnp_rate> min_bps;
    qos<uint32_t>  ttl;
    qos<uint32_t>  provision_size;

    qos_params(qos<uint16_t> chunk_size, qos<ksnp_rate> min_bps, qos<uint32_t> ttl, qos<uint32_t> provision_size)
        : chunk_size(std::move(chunk_size))
        , min_bps(std::move(min_bps))
        , ttl(std::move(ttl))
        , provision_size(std::move(provision_size))
    {}

    explicit qos_params(ksnp_stream_qos_params const *parameters)
        : chunk_size(parameters->chunk_size)
        , min_bps(parameters->min_bps)
        , ttl(parameters->ttl)
        , provision_size(parameters->provision_size)
    {}

    [[nodiscard]] auto as_struct() const -> ksnp_stream_qos_params;
};

}  // namespace pyksnp::stream

#include <nanobind/stl/tuple.h>
#include <nanobind/stl/variant.h>

namespace nanobind::detail
{

template<>
struct type_caster<pyksnp::stream::address> {
    using target = pyksnp::stream::address;
    using base   = pyksnp::stream::address::base;

    // NOLINTNEXTLINE
    NB_TYPE_CASTER(target, type_caster<base>::Name)

    auto from_python(handle src, uint8_t flags, cleanup_list *cleanup) noexcept -> bool
    {
        make_caster<base> caster;

        if (!caster.from_python(src, flags, cleanup)) {
            return false;
        }

        value = target(caster.operator cast_t<base>());
        return true;
    }

    static auto from_cpp(target const &value, rv_policy policy, cleanup_list *cleanup) noexcept -> handle
    {
        return make_caster<base>::from_cpp(static_cast<base const &>(value), policy, cleanup);
    }
};

template<>
struct type_caster<pyksnp::stream::rate> {
    using target = pyksnp::stream::rate;
    using base   = pyksnp::stream::rate::base;

    // NOLINTNEXTLINE
    NB_TYPE_CASTER(target, type_caster<base>::Name)

    auto from_python(handle src, uint8_t flags, cleanup_list *cleanup) noexcept -> bool
    {
        make_caster<base> caster;

        if (!caster.from_python(src, flags, cleanup)) {
            return false;
        }

        value = target(caster.operator cast_t<base>());
        return true;
    }

    static auto from_cpp(target const &value, rv_policy policy, cleanup_list *cleanup) noexcept -> handle
    {
        return make_caster<base>::from_cpp(static_cast<base const &>(value), policy, cleanup);
    }
};

template<typename T>
struct type_caster<pyksnp::stream::qos<T>> {
    using target = pyksnp::stream::qos<T>;
    using base   = pyksnp::stream::qos<T>::base;

    // NOLINTNEXTLINE
    NB_TYPE_CASTER(target, type_caster<base>::Name)

    auto from_python(handle src, uint8_t flags, cleanup_list *cleanup) noexcept -> bool
    {
        make_caster<base> caster;

        if (!caster.from_python(src, flags, cleanup)) {
            return false;
        }

        value = target(caster.operator cast_t<base>());
        return true;
    }

    static auto from_cpp(target const &value, rv_policy policy, cleanup_list *cleanup) noexcept -> handle
    {
        return make_caster<base>::from_cpp(static_cast<base const &>(value), policy, cleanup);
    }
};

template<>
struct type_caster<pyksnp::stream::stream_id> {
    // NOLINTNEXTLINE
    NB_TYPE_CASTER(pyksnp::stream::stream_id, const_name("UUID"))

    auto from_python(handle src, uint8_t /*flags*/, cleanup_list * /*cleanup*/) noexcept -> bool
    try {
        nanobind::bytes bytes = src.attr("bytes");

#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        std::span data(static_cast<unsigned char const *>(bytes.data()), bytes.size());
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif

        if (data.size() != value.size()) {
            return false;
        }
        std::ranges::copy(data, value.begin());

        return true;
    } catch (...) {
        return false;
    }

    static auto from_cpp(pyksnp::stream::stream_id const &value,
                         rv_policy /*policy*/,
                         cleanup_list * /*cleanup*/) noexcept -> handle
    try {
        using namespace nanobind::literals;

        object uuid_mod  = module_::import_("uuid");
        object uuid_type = uuid_mod.attr("UUID");

        nanobind::bytes bytes{value.data(), value.size()};

        return uuid_type("bytes"_a = bytes).release().ptr();
    } catch (...) {
        return {};
    }
};

}  // namespace nanobind::detail
