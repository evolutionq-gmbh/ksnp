#include <algorithm>
#include <cstring>
#include <span>
#include <tuple>
#include <type_traits>

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
    return std::strcmp(left, right) == 0;
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
        std::span left_values{left.list.values, left.list.count};
        std::span right_values{right.list.values, right.list.count};
        return std::ranges::equal(left_values, right_values);
    }
    case ksnp_qos_type::KSNP_QOS_RANGE:
        return left.range.min == right.range.min && left.range.max == right.range.max;
    }
    return false;
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
    return std::ranges::equal(std::span{left.data, left.len}, std::span{right.data, right.len});
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
    return compare1(left, right);
}

auto inline operator==(ksnp_server_event_error const &left, ksnp_server_event_error const &right) -> bool
{
    return compare_eq(left.code, right.code) && compare_eq(left.description, right.description);
}
