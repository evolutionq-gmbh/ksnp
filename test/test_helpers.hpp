#pragma once

#include <algorithm>
#include <cstring>
#include <format>
#include <iostream>
#include <span>
#include <tuple>
#include <type_traits>
#include <variant>

#include <json-c/json_object.h>

#include "ksnp/client.h"
#include "ksnp/messages.h"
#include "ksnp/server.h"
#include "ksnp/types.h"

template<typename T>
auto compare_eq(T left, T right) -> bool
{
    if constexpr (std::is_pointer_v<std::remove_reference_t<std::decay_t<T>>>) {
        return compare_eq(*left, *right);
    }
    return left == right;
}

template<>
auto inline compare_eq(char const *left, char const *right) -> bool
{
    if (left == nullptr || right == nullptr) {
        return left == right;
    }
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    return std::strcmp(left, right) == 0;
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
}

template<>
auto inline compare_eq(json_object *left, json_object *right) -> bool
{
    if (left == nullptr || right == nullptr) {
        return left == right;
    }
    return json_object_equal(left, right) == 1;
}

template<>
auto inline compare_eq(json_object const *left, json_object const *right) -> bool
{
    return compare_eq(const_cast<json_object *>(left), const_cast<json_object *>(right));
}

template<typename T>
auto inline compare_qos(T const &left, T const &right) -> bool
{
    if (left.type != right.type) {
        return false;
    }
    switch (left.type) {
    case ksnp_qos_type::KSNP_QOS_NONE:
    case ksnp_qos_type::KSNP_QOS_NULL:
        return true;
    case ksnp_qos_type::KSNP_QOS_LIST: {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        std::span left_values{left.list.values, left.list.count};
        std::span right_values{right.list.values, right.list.count};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
        return std::ranges::equal(left_values, right_values);
    }
    case ksnp_qos_type::KSNP_QOS_RANGE:
        return left.range.min == right.range.min && left.range.max == right.range.max;
    default:
        return false;
    }
}

template<typename T>
auto compare1(T const &left, T const &right) -> bool  // NOLINT(bugprone-easily-swappable-parameters)
{
    auto [l1] = left;
    auto [r1] = right;
    return compare_eq(l1, r1);
}

template<typename T>
auto compare2(T const &left, T const &right) -> bool  // NOLINT(bugprone-easily-swappable-parameters)
{
    auto [l1, l2] = left;
    auto [r1, r2] = right;
    return compare_eq(l1, r1) && compare_eq(l2, r2);
}

template<typename T>
auto compare3(T const &left, T const &right) -> bool  // NOLINT(bugprone-easily-swappable-parameters)
{
    auto [l1, l2, l3] = left;
    auto [r1, r2, r3] = right;
    return compare_eq(l1, r1) && compare_eq(l2, r2) && compare_eq(l3, r3);
}

auto inline operator==(ksnp_address const &left, ksnp_address const &right)
{
    return compare_eq(left.sae, right.sae) && compare_eq(left.network, right.network);
}

auto inline operator==(ksnp_rate const &left, ksnp_rate const &right)
{
    return std::tie(left.bits, left.seconds) == std::tie(right.bits, right.seconds);
}

auto inline operator==(ksnp_data const &left, ksnp_data const &right)
{
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    auto left_data  = std::span{left.data, left.len};
    auto right_data = std::span{right.data, right.len};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    return std::ranges::equal(left_data, right_data);
}

auto inline operator==(ksnp_stream_open_params const &left, ksnp_stream_open_params const &right) -> bool
{
    return std::ranges::equal(left.stream_id, right.stream_id)
        && std ::tie(left.source,
                     left.destination,
                     left.chunk_size,
                     left.capacity,
                     left.min_bps,
                     left.max_bps,
                     left.ttl,
                     left.provision_size)
               == std::tie(right.source,
                           right.destination,
                           right.chunk_size,
                           right.capacity,
                           right.min_bps,
                           right.max_bps,
                           right.ttl,
                           right.provision_size)
        && compare_eq(left.required_extensions, right.required_extensions)
        && compare_eq(left.extensions, right.extensions);
}

auto inline operator==(ksnp_qos_u16 const &left, ksnp_qos_u16 const &right) -> bool
{
    return compare_qos(left, right);
}

auto inline operator==(ksnp_qos_u32 const &left, ksnp_qos_u32 const &right) -> bool
{
    return compare_qos(left, right);
}

auto inline operator==(ksnp_qos_rate const &left, ksnp_qos_rate const &right) -> bool
{
    return compare_qos(left, right);
}

auto inline operator==(ksnp_stream_accepted_params const &left, ksnp_stream_accepted_params const &right) -> bool
{
    return std::ranges::equal(left.stream_id, right.stream_id)
        && std ::tie(left.chunk_size, left.position, left.max_key_delay, left.min_bps, left.provision_size)
               == std::tie(right.chunk_size, right.position, right.max_key_delay, right.min_bps, right.provision_size)
        && compare_eq(left.extensions, right.extensions);
}

auto inline operator==(ksnp_stream_qos_params const &left, ksnp_stream_qos_params const &right) -> bool
{
    return std ::tie(left.chunk_size, left.min_bps, left.ttl, left.provision_size)
            == std::tie(right.chunk_size, right.min_bps, right.ttl, right.provision_size)
        && compare_eq(left.extensions, right.extensions);
}

auto inline operator==(ksnp_msg_error const &left, ksnp_msg_error const &right) -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_msg_version const &left, ksnp_msg_version const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_msg_open_stream const &left, ksnp_msg_open_stream const &right) -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_msg_open_stream_reply const &left, ksnp_msg_open_stream_reply const &right) -> bool
{
    if (left.code != right.code) {
        return false;
    }

    bool param_eq;
    if (left.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
        param_eq = compare_eq(*left.parameters.reply, *right.parameters.reply);
    } else {
        param_eq = compare_eq(*left.parameters.qos, *right.parameters.qos);
    }
    return param_eq && compare_eq(left.message, right.message);
}

auto inline operator==(ksnp_msg_close_stream const &left, ksnp_msg_close_stream const &right) -> bool
{
    (void)left;
    (void)right;
    return true;
}

auto inline operator==(ksnp_msg_close_stream_notify const &left, ksnp_msg_close_stream_notify const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_msg_close_stream_reply const &left, ksnp_msg_close_stream_reply const &right) -> bool
{
    (void)left;
    (void)right;
    return true;
}

auto inline operator==(ksnp_msg_suspend_stream const &left, ksnp_msg_suspend_stream const &right) -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_msg_suspend_stream_notify const &left, ksnp_msg_suspend_stream_notify const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_msg_suspend_stream_reply const &left, ksnp_msg_suspend_stream_reply const &right) -> bool
{
    return compare3(left, right);
}

auto inline operator==(ksnp_msg_capacity_notify const &left, ksnp_msg_capacity_notify const &right) -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_msg_key_data_notify const &left, ksnp_msg_key_data_notify const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_msg_keep_alive_stream const &left, ksnp_msg_keep_alive_stream const &right) -> bool
{
    return std::ranges::equal(left.key_stream_id, right.key_stream_id);
}

auto inline operator==(ksnp_msg_keep_alive_stream_reply const &left, ksnp_msg_keep_alive_stream_reply const &right)
    -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_client_event_handshake const &left, ksnp_client_event_handshake const &right) -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_client_event_stream_open const &left, ksnp_client_event_stream_open const &right) -> bool
{
    if (left.code != right.code) {
        return false;
    }

    bool param_eq;
    if (left.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
        param_eq = compare_eq(*left.parameters.reply, *right.parameters.reply);
    } else {
        if (left.parameters.qos == nullptr) {
            param_eq = left.parameters.qos == right.parameters.qos;
        } else {
            param_eq = compare_eq(*left.parameters.qos, *right.parameters.qos);
        }
    }
    return param_eq && compare_eq(left.message, right.message);
}

auto inline operator==(ksnp_client_event_stream_close const &left, ksnp_client_event_stream_close const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_client_event_stream_suspend const &left, ksnp_client_event_stream_suspend const &right)
    -> bool
{
    return compare3(left, right);
}

auto inline operator==(ksnp_client_event_key_data const &left, ksnp_client_event_key_data const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_client_event_keep_alive const &left, ksnp_client_event_keep_alive const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_client_event_error const &left, ksnp_client_event_error const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_server_event_handshake const &left, ksnp_server_event_handshake const &right) -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_server_event_open_stream const &left, ksnp_server_event_open_stream const &right) -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_server_event_close_stream const &left, ksnp_server_event_close_stream const &right) -> bool
{
    (void)left;
    (void)right;
    return true;
}

auto inline operator==(ksnp_server_event_suspend_stream const &left, ksnp_server_event_suspend_stream const &right)
    -> bool
{
    return compare1(left, right);
}

auto inline operator==(ksnp_server_event_new_capacity const &left, ksnp_server_event_new_capacity const &right) -> bool
{
    return compare2(left, right);
}

auto inline operator==(ksnp_server_event_keep_alive const &left, ksnp_server_event_keep_alive const &right) -> bool
{
    return std::ranges::equal(std::span{left.stream_id}, std::span{right.stream_id});
}

auto inline operator==(ksnp_server_event_error const &left, ksnp_server_event_error const &right) -> bool
{
    return compare_eq(left.code, right.code) && compare_eq(left.description, right.description);
}

// Forward formatting for generic enums to formatting of their underlying
// types.
template<typename Enum>
requires std::is_enum_v<Enum>
struct enum_formatter {
private:
    using U = std::underlying_type_t<Enum>;
    std::formatter<U> underlying_fmt;

public:
    constexpr auto parse(std::format_parse_context &ctx)
    {
        return underlying_fmt.parse(ctx);
    }

    auto format(Enum const &value, std::format_context &ctx) const
    {
        return underlying_fmt.format(static_cast<U>(value), ctx);
    }
};

template<>
struct std::formatter<ksnp_status_code> : public enum_formatter<ksnp_status_code> {};
template<>
struct std::formatter<ksnp_error_code> : public enum_formatter<ksnp_error_code> {};

static constexpr char const *sep = ", ";

// NOLINTBEGIN(readability-identifier-length, readability-named-parameter, hicpp-named-parameter)

// Forward output stream operator for generic enums to the output stream
// operator of uint64_t.
template<typename Enum>
inline auto operator<<(std::ostream &os, Enum const &value) -> std::ostream &
requires std::is_enum_v<Enum> && std::is_integral_v<std::underlying_type_t<Enum>>
{
    return os << +static_cast<std::underlying_type_t<Enum>>(value);
}

inline auto operator<<(std::ostream &os, ksnp_key_stream_id const &ksid) -> std::ostream &
{
    for (auto const &byte: ksid) {
        os << std::format("{:02X}", byte);
    }
    return os;
}

inline auto operator<<(std::ostream &os, ksnp_address const &addr) -> std::ostream &
{
    return os << "{" << addr.sae << sep << addr.network << "}";
}

inline auto operator<<(std::ostream &os, ksnp_rate const &rate) -> std::ostream &
{
    return os << "{" << rate.bits << sep << rate.seconds << "}";
}

inline auto operator<<(std::ostream &os, json_object const *obj) -> std::ostream &
{
    return os << (obj != nullptr ? "{...}" : "null");
}

inline auto operator<<(std::ostream &os, ksnp_data const &data) -> std::ostream &
{
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    auto buffer = std::span{data.data, data.len};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    for (auto const &byte: buffer) {
        os << std::format("{:02x}", byte);
    }
    return os;
}

template<typename A, typename B>
concept same_decay_as = std::same_as<std::decay_t<A>, std::decay_t<B>>;

template<typename Qos>
concept qos_type = std::is_class_v<Qos> && requires(Qos qos) {
    { qos.type } -> same_decay_as<ksnp_qos_type>;
    { qos.none } -> same_decay_as<int>;
    { qos.range.max } -> same_decay_as<decltype(qos.range.min)>;
    { qos.list.values } -> same_decay_as<decltype(qos.range.min) const *>;
    { qos.list.count } -> same_decay_as<size_t>;
};

template<typename T>
concept ostreamable = requires(std::ostream &os, T const &value) {
    { os << value } -> std::same_as<std::ostream &>;
};

template<qos_type Q>
auto operator<<(std::ostream &os, Q const &qos) -> std::ostream &
requires ostreamable<decltype(qos.range.min)>
{
    switch (qos.type) {
    case ksnp_qos_type::KSNP_QOS_NONE:
        return os << "qos{none}";
    case ksnp_qos_type::KSNP_QOS_NULL:
        return os << "qos{null}";
    case ksnp_qos_type::KSNP_QOS_RANGE:
        return os << "qos{" << qos.range.min << sep << qos.range.max << "}";
    case ksnp_qos_type::KSNP_QOS_LIST: {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        auto values = std::span{qos.list.values, qos.list.count};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
        os << "qos[";
        bool first = true;
        for (auto const &value: values) {
            if (!first) {
                os << sep;
            } else {
                first = false;
            }
            os << value;
        }
        return os << "]";
    }
    default:
        return os << "qos{bad type}";
    }
}

inline auto operator<<(std::ostream &os, ksnp_msg_error const &msg) -> std::ostream &
{
    return os << "ksnp_msg_error{" << msg.code << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_version const &msg) -> std::ostream &
{
    return os << "ksnp_msg_version{" << msg.minimum_version << sep << msg.maximum_version << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_open_stream const &msg) -> std::ostream &
{
    if (auto const *open_params = msg.parameters) {
        return os << "ksnp_msg_open_stream{" << open_params->stream_id << sep << open_params->source << sep
                  << open_params->destination << sep << open_params->chunk_size << sep << open_params->capacity << sep
                  << open_params->min_bps << sep << open_params->max_bps << sep << open_params->ttl << sep
                  << open_params->provision_size << sep << open_params->extensions << sep
                  << open_params->required_extensions << "}";
    }
    return os << "ksnp_msg_open_stream{null}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_open_stream_reply const &msg) -> std::ostream &
{
    os << "ksnp_msg_open_stream_reply{0x" << std::format("{:0X}", msg.code) << sep << "{";
    if (msg.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
        if (auto const *reply_params = msg.parameters.reply) {
            os << reply_params->stream_id << sep << reply_params->chunk_size << sep << reply_params->position << sep
               << reply_params->max_key_delay << sep << reply_params->min_bps << sep << reply_params->provision_size
               << sep << reply_params->extensions;
        } else {
            os << "null";
        }
    } else {
        if (auto const *qos = msg.parameters.qos) {
            os << qos->chunk_size << sep << qos->min_bps << sep << qos->ttl << sep << qos->provision_size << sep
               << qos->extensions;
        } else {
            os << "null";
        }
    }
    return os << "}}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_close_stream const &) -> std::ostream &
{
    return os << "ksnp_msg_close_stream{}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_close_stream_reply const &) -> std::ostream &
{
    return os << "ksnp_msg_close_stream_reply{}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_close_stream_notify const &msg) -> std::ostream &
{
    return os << "ksnp_msg_close_stream_notify{" << msg.code << sep << (msg.message != nullptr ? msg.message : "")
              << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_suspend_stream const &msg) -> std::ostream &
{
    return os << "ksnp_msg_suspend_stream{" << msg.timeout << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_suspend_stream_reply const &msg) -> std::ostream &
{
    return os << "ksnp_msg_suspend_stream_reply{" << msg.code << sep << msg.timeout << sep
              << (msg.message != nullptr ? msg.message : "") << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_suspend_stream_notify const &msg) -> std::ostream &
{
    return os << "ksnp_msg_suspend_stream_notify{" << msg.code << sep << msg.timeout << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_keep_alive_stream const &msg) -> std::ostream &
{
    return os << "ksnp_msg_keep_alive_stream{" << msg.key_stream_id << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_keep_alive_stream_reply const &msg) -> std::ostream &
{
    return os << "ksnp_msg_keep_alive_stream_reply{" << msg.code << sep << (msg.message != nullptr ? msg.message : "")
              << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_capacity_notify const &msg) -> std::ostream &
{
    return os << "ksnp_msg_capacity_notify{" << msg.additional_capacity << "}";
}

inline auto operator<<(std::ostream &os, ksnp_msg_key_data_notify const &msg) -> std::ostream &
{
    return os << "ksnp_msg_key_data_notify{" << msg.key_data << sep << msg.parameters << "}";
}

template<ostreamable... Alts>
auto operator<<(std::ostream &os, std::variant<Alts...> const &value) -> std::ostream &
{
    return std::visit(
        [&](auto &&alt) -> std::ostream & {
            return (os << alt);
        },
        value);
}

class const_data : public std::span<uint8_t const>
{
public:
    const_data(char const *_data, size_t _count) noexcept
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        : span(reinterpret_cast<uint8_t const *>(_data), _count)
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    {}
};

inline auto operator""_cdat(char const *str, size_t len) noexcept -> const_data
{
    return const_data{str, len};
}

inline auto operator<<(std::ostream &os, const_data const &data) -> std::ostream &
{
    os << "{";
    for (auto const &byte: data) {
        os << std::format("{:02X}", byte);
    }
    return os << "}";
}

// NOLINTEND(readability-identifier-length, readability-named-parameter, hicpp-named-parameter)
