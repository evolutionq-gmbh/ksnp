#include <algorithm>
#include <cassert>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_tokener.h>
#include <uuid/uuid.h>

#include "helpers.hpp"
#include "ksnp/messages.h"
#include "ksnp/serde.h"

#include "ksnp/types.h"
#include "serde.hpp"

#ifndef JSON_C_OBJECT_ADD_CONSTANT_KEY
// Support for legacy JSON-C versions.
#define JSON_C_OBJECT_ADD_CONSTANT_KEY JSON_C_OBJECT_KEY_IS_CONSTANT
#endif

namespace ksnp
{

auto message::into_message() const noexcept -> ::ksnp_message
{
    auto const visitor = overloads{
        [](ksnp_msg_version msg) -> ksnp_message {
            return ksnp_message{
                .type    = ksnp_message_type::KSNP_MSG_VERSION,
                .version = msg,
            };
        },
        [](ksnp_msg_open_stream msg) -> ksnp_message {
            return ksnp_message{
                .type        = ksnp_message_type::KSNP_MSG_OPEN_STREAM,
                .open_stream = msg,
            };
        },
        [](ksnp_msg_open_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type              = ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY,
                .open_stream_reply = msg,
            };
        },
        [](ksnp_msg_close_stream msg) -> ksnp_message {
            return ksnp_message{
                .type         = ksnp_message_type::KSNP_MSG_CLOSE_STREAM,
                .close_stream = msg,
            };
        },
        [](ksnp_msg_close_stream_notify msg) -> ksnp_message {
            return ksnp_message{
                .type                = ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY,
                .close_stream_notify = msg,
            };
        },
        [](ksnp_msg_close_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type               = ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY,
                .close_stream_reply = msg,
            };
        },
        [](ksnp_msg_suspend_stream msg) -> ksnp_message {
            return ksnp_message{
                .type           = ksnp_message_type::KSNP_MSG_SUSPEND_STREAM,
                .suspend_stream = msg,
            };
        },
        [](ksnp_msg_suspend_stream_notify msg) -> ksnp_message {
            return ksnp_message{
                .type                  = ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY,
                .suspend_stream_notify = msg,
            };
        },
        [](ksnp_msg_suspend_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type                 = ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY,
                .suspend_stream_reply = msg,
            };
        },
        [](ksnp_msg_capacity_notify msg) -> ksnp_message {
            return ksnp_message{
                .type            = ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY,
                .capacity_notify = msg,
            };
        },
        [](ksnp_msg_key_data_notify msg) -> ksnp_message {
            return ksnp_message{
                .type            = ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY,
                .key_data_notify = msg,
            };
        },
        [](ksnp_msg_keep_alive_stream msg) -> ksnp_message {
            return ksnp_message{
                .type              = ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM,
                .keep_alive_stream = msg,
            };
        },
        [](ksnp_msg_keep_alive_stream_reply msg) -> ksnp_message {
            return ksnp_message{
                .type                    = ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY,
                .keep_alive_stream_reply = msg,
            };
        },
        [](ksnp_msg_error msg) -> ksnp_message {
            return ksnp_message{
                .type  = ksnp_message_type::KSNP_MSG_ERROR,
                .error = msg,
            };
        },
    };
    return std::visit(visitor, *this);
}

auto message::from_message(::ksnp_message msg) -> std::optional<message>
{
    switch (msg.type) {
    case ksnp_message_type::KSNP_MSG_ERROR:
        return msg.error;
    case ksnp_message_type::KSNP_MSG_VERSION:
        return msg.version;
    case ksnp_message_type::KSNP_MSG_OPEN_STREAM:
        return msg.open_stream;
    case ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY:
        return msg.open_stream_reply;
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM:
        return msg.close_stream;
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY:
        return msg.close_stream_reply;
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY:
        return msg.close_stream_notify;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM:
        return msg.suspend_stream;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY:
        return msg.suspend_stream_reply;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY:
        return msg.suspend_stream_notify;
    case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM:
        return msg.keep_alive_stream;
    case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY:
        return msg.keep_alive_stream_reply;
    case ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY:
        return msg.capacity_notify;
    case ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY:
        return msg.key_data_notify;
    case ksnp_message_type::KSNP_MSG_NONE:
        return std::nullopt;
    default:
        throw exception(ksnp_error::KSNP_E_INVALID_MESSAGE_TYPE);
    }
}
}  // namespace ksnp

namespace
{
using namespace ksnp;

constexpr zstring_view json_key_ksid                = "key-stream-id"_zsv;
constexpr zstring_view json_key_source              = "source"_zsv;
constexpr zstring_view json_key_destination         = "destination"_zsv;
constexpr zstring_view json_key_chunk_size          = "chunk-size"_zsv;
constexpr zstring_view json_key_capacity            = "capacity"_zsv;
constexpr zstring_view json_key_min_bps             = "min-bps"_zsv;
constexpr zstring_view json_key_max_bps             = "max-bps"_zsv;
constexpr zstring_view json_key_ttl                 = "ttl"_zsv;
constexpr zstring_view json_key_provision_size      = "provision-size"_zsv;
constexpr zstring_view json_key_extensions          = "extensions"_zsv;
constexpr zstring_view json_key_required_extensions = "required-extensions"_zsv;
constexpr zstring_view json_key_position            = "position"_zsv;
constexpr zstring_view json_key_max_key_delay       = "max-key-delay"_zsv;
constexpr zstring_view json_key_address_sae         = "sae"_zsv;
constexpr zstring_view json_key_address_network     = "network"_zsv;
constexpr zstring_view json_key_rate_bits           = "bits"_zsv;
constexpr zstring_view json_key_rate_seconds        = "seconds"_zsv;
constexpr zstring_view json_key_qos_range_min       = "min"_zsv;
constexpr zstring_view json_key_qos_range_max       = "max"_zsv;

template<typename T>
auto check_alloc(T *val) -> T *
{
    if (val == nullptr) {
        throw ksnp::exception(ksnp_error::KSNP_E_NO_MEM);
    }
    return val;
}

auto operator<=>(struct ksnp_rate const &lhs, struct ksnp_rate const &rhs) -> std::strong_ordering
{
    // As detailed in the type's declaration, a denominator of 0 is interpreted
    // as the default of 1.
    auto lhs_sec = lhs.seconds > 0 ? lhs.seconds : 1;
    auto rhs_sec = rhs.seconds > 0 ? rhs.seconds : 1;

    return static_cast<uint64_t>(lhs.bits) * rhs_sec <=> static_cast<uint64_t>(rhs.bits) * lhs_sec;
}

template<std::unsigned_integral TargetUint, typename U8>
[[nodiscard]] constexpr auto uint_from_be(std::span<U8, sizeof(TargetUint)> data) noexcept -> TargetUint
requires(std::is_same_v<std::decay_t<U8>, uint8_t>)
{
    constexpr int BITS = std::numeric_limits<U8>::digits;

    auto val = static_cast<TargetUint>(data[0]);
    if constexpr (sizeof(TargetUint) > 1) {
        for (U8 byte: data.subspan(1)) {
            val <<= BITS;
            val |= byte;
        }
    }
    return val;
}

template<std::unsigned_integral TargetUint, typename U8>
auto load_next(std::span<U8, std::dynamic_extent> &data) -> TargetUint
requires(std::is_same_v<std::decay_t<U8>, uint8_t>)
{
    constexpr size_t COUNT = sizeof(TargetUint);
    if (data.size() < COUNT) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH);
    }

    auto val = uint_from_be<TargetUint>(data.template first<COUNT>());
    data     = data.subspan(COUNT);
    return val;
}

template<typename U8>
auto load_next_u8(std::span<U8> &data) -> uint8_t
{
    return load_next<uint8_t>(data);
}

template<typename U8>
auto load_next_u16(std::span<U8> &data) -> uint16_t
{
    return load_next<uint16_t>(data);
}

template<typename U8>
auto load_next_u32(std::span<U8> &data) -> uint32_t
{
    return load_next<uint32_t>(data);
}

template<typename T, typename U8>
auto load_next_enum(std::span<U8> &data) -> T
{
    return static_cast<T>(load_next<typename std::underlying_type_t<T>>(data));
}

void json_to_stream_id(json_object *obj, ksnp_key_stream_id &stream_id)
{
    if (json_object_get_type(obj) != json_type_string) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
    }
    if (auto const *uuid_str = json_object_get_string(obj);
        uuid_str == nullptr || uuid_parse(uuid_str, std::begin(stream_id)) != 0) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL, "invalid UUID");
    }
}

template<std::unsigned_integral TargetUint>
[[nodiscard]] auto json_to_uint(json_object const *obj) -> TargetUint
{
    if (json_object_get_type(obj) != json_type_int) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
    }
    errno     = 0;
    auto sval = json_object_get_int64(obj);
    if (errno != 0 || sval < 0) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL, "integer out of bounds");
    }
    errno    = 0;
    auto val = json_object_get_uint64(obj);
    if (errno != 0 || !std::in_range<TargetUint>(val)) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL, "integer out of bounds");
    }
    return static_cast<TargetUint>(val);
}

[[nodiscard]] auto json_to_u16(json_object const *obj) -> uint16_t
{
    return json_to_uint<uint16_t>(obj);
}

[[nodiscard]] auto json_to_u32(json_object const *obj) -> uint32_t
{
    return json_to_uint<uint32_t>(obj);
}

template<typename... string_views>
[[nodiscard]] constexpr auto key_allowed(std::string_view key, string_views... allowed_keys) noexcept -> bool
{
    return ((key == allowed_keys) || ...);
}

template<typename... string_views>
void check_subobject_allowed_keys(json_object const *obj, string_views... allowed_keys)
{
    if (json_object_get_type(obj) != json_type_object) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
    }
    auto end_iter = json_object_iter_end(obj);
    // Unfortunately, json-c does not currently provide an API for const
    // iterators. Since we're only peeking at keys here, and do not
    // modify anything, we const_cast the object to preserve const
    // correctness of the calling function tree.
    for (auto it = json_object_iter_begin(const_cast<json_object *>(obj)); json_object_iter_equal(&it, &end_iter) == 0;
         json_object_iter_next(&it)) {
        if (!key_allowed(json_object_iter_peek_name(&it), allowed_keys...)) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_KEY);
        }
    }
}

[[nodiscard]] auto get_subobject_string(json_object const *obj, zstring_view key) -> json_ptr
{
    json_object *subobj = nullptr;
    if (json_object_object_get_ex(obj, key.c_str(), &subobj) == 1 && json_object_get_type(subobj) != json_type_string) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
    }
    // If obj has no entry for the given key, subobj will still be nullptr
    // here.
    return json_ptr(subobj != nullptr ? json_object_get(subobj) : nullptr);
}

[[nodiscard]] auto json_to_address(json_object const *obj) -> stream_address
{
    // First check the type of the subobject, and whether it contains
    // unknown keys.
    check_subobject_allowed_keys(obj, json_key_address_sae, json_key_address_network);

    // Extract address strings.
    return {get_subobject_string(obj, json_key_address_sae), get_subobject_string(obj, json_key_address_network)};
}

[[nodiscard]] auto json_to_rate(json_object const *obj) -> ksnp_rate
{
    // First check the type of the subobject, and whether it contains
    // unknown keys.
    check_subobject_allowed_keys(obj, json_key_rate_bits, json_key_rate_seconds);

    // The seconds member is optional. The bits member is required.
    ksnp_rate    rate = {.bits = 0, .seconds = 0};
    json_object *subobj;
    if (json_object_object_get_ex(obj, json_key_rate_bits.c_str(), &subobj) != 1) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_KEY_MISSING);
    }
    rate.bits = json_to_u32(subobj);
    if (json_object_object_get_ex(obj, json_key_rate_seconds.c_str(), &subobj) == 1) {
        rate.seconds = json_to_u32(subobj);
        if (rate.seconds == 0) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
        }
    }
    return rate;
}

void add_stream_id_to_json(json_object *obj, zstring_view key, uuid_t const &stream_id)
{
    // An all-zero array means the field is unset.
    if (uuid_is_null(std::begin(stream_id)) == 1) {
        return;
    }
    std::array<char, UUID_STR_LEN> uuid_str{};
    uuid_unparse_lower(std::begin(stream_id), uuid_str.data());

    json_object_object_add_ex(obj,
                              key.c_str(),
                              check_alloc(json_object_new_string_len(uuid_str.data(), uuid_str.size() - 1)),
                              JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
}

void add_string_to_json(json_object *obj, zstring_view key, char const *str)
{
    json_object_object_add_ex(obj,
                              key.c_str(),
                              check_alloc(json_object_new_string(str)),
                              JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
}

void add_address_to_json(json_object *obj, zstring_view key, struct ksnp_address address)
{
    // Do not add an empty address subobject.
    if (address.sae == nullptr && address.network == nullptr) {
        return;
    }

    auto address_obj = json_ptr(check_alloc(json_object_new_object()));
    if (address.sae != nullptr) {
        add_string_to_json(address_obj.get(), json_key_address_sae, address.sae);
    }
    if (address.network != nullptr) {
        add_string_to_json(address_obj.get(), json_key_address_network, address.network);
    }

    json_object_object_add_ex(
        obj, key.c_str(), address_obj.release(), JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
}

template<std::unsigned_integral SourceUint>
void add_uint_to_json(json_object *obj, zstring_view key, SourceUint val)
{
    // For all our integer fields, 0 means the field is unset.
    if (val != 0) {
        json_object_object_add_ex(obj,
                                  key.c_str(),
                                  check_alloc(json_object_new_uint64(val)),
                                  JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
    }
}

[[nodiscard]] auto rate_to_json(struct ksnp_rate rate) -> json_object *
{
    // A numerator of 0 means the field is unset.
    if (rate.bits == 0) {
        return nullptr;
    }

    auto rate_obj = json_ptr(check_alloc(json_object_new_object()));
    add_uint_to_json(rate_obj.get(), json_key_rate_bits, rate.bits);
    if (rate.seconds != 0) {
        add_uint_to_json(rate_obj.get(), json_key_rate_seconds, rate.seconds);
    }

    return rate_obj.release();
}

void add_rate_to_json(json_object *obj, zstring_view key, struct ksnp_rate rate)
{
    auto *rate_obj = rate_to_json(rate);
    // Do not add unset fields.
    if (rate_obj != nullptr) {
        json_object_object_add_ex(
            obj, key.c_str(), rate_obj, JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
    }
}

void add_subobject_to_json(json_object *obj, zstring_view key, json_object *subobj)
{
    if (subobj != nullptr) {
        // Increment refcount of the object: do NOT transfer ownership to
        // the parent object. Instead, the main object will decrement the
        // refcount again upon going out of scope; ownership remains with
        // the caller.
        json_object_object_add_ex(
            obj, key.c_str(), json_object_get(subobj), JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
    }
}

template<typename QosExpectedValue, typename BaseType, json_object *(*ToJson)(BaseType)>
void add_qos_to_json(json_object *obj, zstring_view key, QosExpectedValue qos)
requires std::convertible_to<decltype(std::declval<QosExpectedValue>().range.min), BaseType>
{
    switch (qos.type) {
    case ksnp_qos_type::KSNP_QOS_NONE:
        break;
    case ksnp_qos_type::KSNP_QOS_NULL:
        json_object_object_add_ex(
            obj, key.c_str(), json_object_new_null(), JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
        break;
    case ksnp_qos_type::KSNP_QOS_RANGE: {
        auto range_obj = json_ptr(check_alloc(json_object_new_object()));
        json_object_object_add_ex(range_obj.get(),
                                  json_key_qos_range_min.c_str(),
                                  check_alloc(ToJson(qos.range.min)),
                                  JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
        json_object_object_add_ex(range_obj.get(),
                                  json_key_qos_range_max.c_str(),
                                  check_alloc(ToJson(qos.range.max)),
                                  JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
        json_object_object_add_ex(
            obj, key.c_str(), range_obj.release(), JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
        break;
    }
    case ksnp_qos_type::KSNP_QOS_LIST: {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        auto list = std::span(qos.list.values, qos.list.count);
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
        if (!std::in_range<int>(list.size())) {
            throw exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
        }
        auto array_obj = json_ptr(check_alloc(json_object_new_array_ext(static_cast<int>(list.size()))));
        for (auto item: list) {
            if (json_object_array_add(array_obj.get(), check_alloc(ToJson(item))) != 0) {
                throw ksnp::exception(ksnp_error::KSNP_E_NO_MEM);
            }
        }
        json_object_object_add_ex(
            obj, key.c_str(), array_obj.release(), JSON_C_OBJECT_ADD_CONSTANT_KEY | JSON_C_OBJECT_ADD_KEY_IS_NEW);
        break;
    }
    default:
        throw std::logic_error("invalid qos type");
    }
}

void add_qos_u16_to_json(json_object *obj, zstring_view key, ksnp_qos_u16 qos)
{
    add_qos_to_json<ksnp_qos_u16, uint64_t, json_object_new_uint64>(obj, key, qos);
}

void add_qos_u32_to_json(json_object *obj, zstring_view key, ksnp_qos_u32 qos)
{
    add_qos_to_json<ksnp_qos_u32, uint64_t, json_object_new_uint64>(obj, key, qos);
}

void add_qos_rate_to_json(json_object *obj, zstring_view key, ksnp_qos_rate qos)
{
    add_qos_to_json<ksnp_qos_rate, struct ksnp_rate, rate_to_json>(obj, key, qos);
}

template<typename T>
void check_qos_range(T const &qos_value)
{
    if (qos_value.type == ksnp_qos_type::KSNP_QOS_RANGE) {
        if (qos_value.range.min > qos_value.range.max) {
            throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
        }
    }
}

template<typename T>
using qos_value = std::variant<std::monostate, std::tuple<T, T>, std::vector<T>>;

template<typename T>
[[nodiscard]] auto json_to_qos_value(json_object const *obj) -> T;

template<>
[[nodiscard]] auto json_to_qos_value(json_object const *obj) -> uint16_t
{
    return json_to_uint<uint16_t>(obj);
}

template<>
[[nodiscard]] auto json_to_qos_value(json_object const *obj) -> uint32_t
{
    return json_to_uint<uint32_t>(obj);
}

template<>
[[nodiscard]] auto json_to_qos_value(json_object const *obj) -> ksnp_rate
{
    return json_to_rate(obj);
}

template<typename T>
[[nodiscard]] auto json_to_qos_range(json_object const *obj) -> std::tuple<T, T>
{
    // First check the type of the subobject, and whether it contains
    // unknown keys.
    check_subobject_allowed_keys(obj, json_key_qos_range_min, json_key_qos_range_max);

    // Get the min and max subobjects and parse them using the given
    // callback.
    json_object *min_obj;
    json_object *max_obj;
    if (!json_object_object_get_ex(obj, json_key_qos_range_min.c_str(), &min_obj)
        || !json_object_object_get_ex(obj, json_key_qos_range_max.c_str(), &max_obj)) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_KEY_MISSING);
    }

    auto min_val = json_to_qos_value<T>(min_obj);
    auto max_val = json_to_qos_value<T>(max_obj);

    if (min_val > max_val) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
    }

    return {min_val, max_val};
}

template<typename T>
[[nodiscard]] auto json_to_qos_list(json_object const *obj) -> std::vector<T>
{
    auto count = json_object_array_length(obj);
    if (count == 0) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL, "empty QoS expected array");
    }

    std::vector<T> qos_list;
    qos_list.reserve(count);
    for (size_t i = 0; i < count; i++) {
        auto *entry = json_object_array_get_idx(obj, i);
        qos_list.push_back(json_to_qos_value<T>(entry));
    }

    return qos_list;
}

template<typename T>
[[nodiscard]] auto json_to_qos(json_object const *obj) -> qos_value<T>
{
    switch (json_object_get_type(obj)) {
    case json_type_null:
        return {};
    case json_type_object:
        return json_to_qos_range<T>(obj);
    case json_type_array:
        return json_to_qos_list<T>(obj);
    case json_type_boolean:
    case json_type_double:
    case json_type_int:
    case json_type_string:
    default:
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
    }
}
template<typename T, typename U>
void set_qos(qos_value<T> value, U &dest, std::vector<T> &storage)
{
    std::visit(overloads{
                   [&dest](std::monostate) -> void {
                       dest.type = ksnp_qos_type::KSNP_QOS_NULL;
                       dest.none = 0;
                   },
                   [&dest](std::tuple<T, T> value) -> void {
                       dest.type      = ksnp_qos_type::KSNP_QOS_RANGE;
                       dest.range.min = std::get<0>(value);
                       dest.range.max = std::get<1>(value);
                   },
                   [&dest, &storage](std::vector<T> value) -> void {
                       dest.type        = ksnp_qos_type::KSNP_QOS_LIST;
                       dest.list.values = value.data();
                       dest.list.count  = value.size();
                       storage          = std::move(value);
                   },
               },
               std::move(value));
}

[[nodiscard]] auto json_to_stream_params(json_object *json) -> stream_open_params
{
    struct ksnp_stream_open_params params{};
    stream_address                 source;
    stream_address                 destination;
    json_obj                       extensions;
    json_obj                       required_extensions;

    auto end_iter = json_object_iter_end(json);
    for (auto it = json_object_iter_begin(json); json_object_iter_equal(&it, &end_iter) == 0;
         json_object_iter_next(&it)) {
        std::string_view name  = json_object_iter_peek_name(&it);
        auto            *value = json_object_iter_peek_value(&it);
        if (name == json_key_ksid) {
            json_to_stream_id(value, params.stream_id);
        } else if (name == json_key_source) {
            source        = json_to_address(value);
            params.source = source.get_address();
        } else if (name == json_key_destination) {
            destination        = json_to_address(value);
            params.destination = destination.get_address();
        } else if (name == json_key_chunk_size) {
            params.chunk_size = json_to_u16(value);
        } else if (name == json_key_capacity) {
            params.capacity = json_to_u32(value);
        } else if (name == json_key_min_bps) {
            params.min_bps = json_to_rate(value);
        } else if (name == json_key_max_bps) {
            params.max_bps = json_to_rate(value);
        } else if (name == json_key_ttl) {
            params.ttl = json_to_u32(value);
        } else if (name == json_key_provision_size) {
            params.provision_size = json_to_u32(value);
        } else if (name == json_key_extensions) {
            extensions        = json_obj(value);
            params.extensions = *extensions;
        } else if (name == json_key_required_extensions) {
            if (json_object_get_type(value) != json_type_object) {
                throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
            }
            required_extensions        = json_obj(value);
            params.required_extensions = *required_extensions;
        } else {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_KEY);
        }
    }

    // Check that required fields exist. Check constraints on numerical
    // limits which are not automatically satisfied due to type limits.
    if (params.destination.sae == nullptr) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_KEY_MISSING);
    }
    if (params.chunk_size > KSNP_MAX_CHUNK_SIZE || (params.max_bps.bits > 0 && params.max_bps < params.min_bps)
        || (params.provision_size > 0 && params.provision_size < params.chunk_size)) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
    }

    return {params, std::move(source), std::move(destination), std::move(extensions), std::move(required_extensions)};
}

[[nodiscard]] auto json_to_stream_reply_params(json_object *json) -> stream_accepted_params
{
    struct ksnp_stream_accepted_params params{};
    json_obj                           extensions;
    bool                               bps_set = false;

    auto end_iter = json_object_iter_end(json);
    for (auto it = json_object_iter_begin(json); json_object_iter_equal(&it, &end_iter) == 0;
         json_object_iter_next(&it)) {
        auto const *name  = json_object_iter_peek_name(&it);
        auto       *value = json_object_iter_peek_value(&it);
        if (name == json_key_ksid) {
            json_to_stream_id(value, params.stream_id);
        } else if (name == json_key_chunk_size) {
            params.chunk_size = json_to_u16(value);
        } else if (name == json_key_position) {
            params.position = json_to_u32(value);
        } else if (name == json_key_max_key_delay) {
            params.max_key_delay = json_to_u32(value);
        } else if (name == json_key_min_bps) {
            bps_set        = true;
            params.min_bps = json_to_rate(value);
        } else if (name == json_key_provision_size) {
            params.provision_size = json_to_u32(value);
        } else if (name == json_key_extensions) {
            extensions        = json_obj(value);
            params.extensions = *extensions;
        } else {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_KEY);
        }
    }

    // Check that required fields exist. Check constraints on numerical
    // limits which are not automatically satisfied due to type limits.
    if (!bps_set) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_KEY_MISSING);
    }
    if (params.chunk_size > KSNP_MAX_CHUNK_SIZE
        || (params.provision_size > 0 && params.provision_size < params.chunk_size)) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
    }

    return {params, std::move(extensions)};
}

[[nodiscard]] auto json_to_stream_qos_params(json_object *json) -> stream_qos_params
{
    struct ksnp_stream_qos_params params{
        .chunk_size     = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
        .min_bps        = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
        .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
        .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
        .extensions     = nullptr,
    };
    std::vector<uint16_t>  chunk_size_list;
    std::vector<ksnp_rate> min_bps_list;
    std::vector<uint32_t>  ttl_list;
    std::vector<uint32_t>  provision_size_list;
    json_obj               extensions;

    auto end_iter = json_object_iter_end(json);
    for (auto it = json_object_iter_begin(json); json_object_iter_equal(&it, &end_iter) == 0;
         json_object_iter_next(&it)) {
        std::string_view name  = json_object_iter_peek_name(&it);
        auto            *value = json_object_iter_peek_value(&it);

        if (name == json_key_chunk_size) {
            set_qos(json_to_qos<uint16_t>(value), params.chunk_size, chunk_size_list);
        } else if (name == json_key_min_bps) {
            set_qos(json_to_qos<ksnp_rate>(value), params.min_bps, min_bps_list);
        } else if (name == json_key_ttl) {
            set_qos(json_to_qos<uint32_t>(value), params.ttl, ttl_list);
        } else if (name == json_key_provision_size) {
            set_qos(json_to_qos<uint32_t>(value), params.provision_size, provision_size_list);
        } else if (name == json_key_extensions) {
            extensions        = json_obj(value);
            params.extensions = *extensions;
        } else {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_KEY);
        }
    }

    // Check constraints for chunk size, everything else is enforced by
    // type limits.
    switch (params.chunk_size.type) {
    case ksnp_qos_type::KSNP_QOS_RANGE:
        if (params.chunk_size.range.max > KSNP_MAX_CHUNK_SIZE) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
        }
        break;
    case ksnp_qos_type::KSNP_QOS_LIST: {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        auto values = std::span{params.chunk_size.list.values, params.chunk_size.list.count};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
        for (auto val: values) {
            if (val > KSNP_MAX_CHUNK_SIZE) {
                throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
            }
        }
        break;
    }
    case ksnp_qos_type::KSNP_QOS_NONE:
    case ksnp_qos_type::KSNP_QOS_NULL:
    default:
        break;
    }

    return {params,
            std::move(chunk_size_list),
            std::move(min_bps_list),
            std::move(ttl_list),
            std::move(provision_size_list),
            std::move(extensions)};
}

}  // namespace

namespace ksnp
{

void message_context::free_last_message()
{
    if (!this->last_message_len.has_value()) {
        return;
    }

    this->input_data.consume(*this->last_message_len);

    this->last_message_len.reset();
    this->status_message.clear();
    this->last_message_payload = std::monostate{};
}

auto message_context::load_next_string(std::span<uint8_t const> &data) -> char const *
{
    if (data.empty()) {
        this->status_message.clear();
        return nullptr;
    }
    this->status_message.assign(data.begin(), data.end());
    data = data.subspan(data.size());
    return this->status_message.c_str();
}

auto message_context::load_next_json(std::span<uint8_t const> &data, size_t json_len) -> json_obj
{
    // json_tokener_parse_ex reads the length as `int`.
    if (json_len > data.size() || !std::in_range<int>(json_len)) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_LENGTH, "JSON length exceeds maximum");
    }

    if (json_len == 0) {
        return {};
    }

    // Wrap the tokener in a unique_obj so it is properly freed in case of
    // an exception.
    unique_obj<json_tokener *, json_tokener_free> tok(json_tokener_new());

    auto const *data_ptr = data.data();
    auto *obj = json_tokener_parse_ex(tok.get(), reinterpret_cast<char const *>(data_ptr), static_cast<int>(json_len));
    if (obj == nullptr) {
        this->status_message = json_tokener_error_desc(json_tokener_get_error(tok.get()));
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON, this->status_message.c_str());
    }

    // Wrap the JSON object in a unique_ptr so it automatically frees its
    // data when it goes out of scope. If the function is successful, store
    // this object in the message context to extend the lifetime of all
    // pointers into the JSON data.
    json_obj raii_obj(obj);

    // After the parsed JSON object, only whitespace is allowed within the
    // JSON field of the message (as defined by `json_len`).
    // Note that the JSON library only parses up to `json_len` bytes, so
    // `parsed_len <= json_len`.
    auto parsed_len = json_tokener_get_parse_end(tok.get());
    if (!std::ranges::all_of(data.subspan(parsed_len, json_len - parsed_len), ::isspace)) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_LENGTH, "extra data after JSON object");
    }

    data = data.subspan(json_len);

    return raii_obj;
}

void message_context::write_json(json_object *obj, json_ser_flag flag)
{
    size_t           json_len;
    auto const      *json_ptr = check_alloc(json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN, &json_len));
    std::string_view json(json_ptr, json_len);
    if (!std::in_range<uint16_t>(json_len)) {
        throw exception(ksnp_error::KSNP_E_SER_JSON_TOO_LARGE);
    }
    if (flag == json_ser_flag::with_length) {
        this->write_u16(static_cast<uint16_t>(json_len));
    }
    this->output_data.append_exact(reinterpret_cast<unsigned char const *>(json.data()), json.size());
}

void message_context::write_message(char const *msg)
{
    if (msg == nullptr) {
        return;
    }
    std::string_view msg_view(msg);
    this->output_data.append_exact(reinterpret_cast<unsigned char const *>(msg_view.data()), msg_view.size());
}

void message_context::write_parameters(ksnp_stream_open_params const *params)
{
    if (params->destination.sae == nullptr || params->chunk_size > KSNP_MAX_CHUNK_SIZE
        || (params->max_bps.bits > 0 && params->max_bps < params->min_bps)
        || (params->provision_size > 0 && params->provision_size < params->chunk_size)) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    json_ptr main_obj(json_object_new_object());
    auto    *obj = main_obj.get();

    add_stream_id_to_json(obj, json_key_ksid, {params->stream_id});
    add_address_to_json(obj, json_key_source, params->source);
    add_address_to_json(obj, json_key_destination, params->destination);
    add_uint_to_json(obj, json_key_chunk_size, params->chunk_size);
    add_uint_to_json(obj, json_key_capacity, params->capacity);
    add_rate_to_json(obj, json_key_min_bps, params->min_bps);
    add_rate_to_json(obj, json_key_max_bps, params->max_bps);
    add_uint_to_json(obj, json_key_ttl, params->ttl);
    add_uint_to_json(obj, json_key_provision_size, params->provision_size);
    add_subobject_to_json(obj, json_key_extensions, params->extensions);
    add_subobject_to_json(obj, json_key_required_extensions, params->required_extensions);

    this->write_json(obj, json_ser_flag::plain);
}

void message_context::write_reply_parameters(ksnp_stream_accepted_params const *params)
{
    if (params->min_bps.bits == 0 || params->chunk_size > KSNP_MAX_CHUNK_SIZE
        || (params->provision_size > 0 && params->provision_size < params->chunk_size)) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    json_ptr main_obj(json_object_new_object());
    auto    *obj = main_obj.get();

    add_stream_id_to_json(obj, json_key_ksid, {params->stream_id});
    add_uint_to_json(obj, json_key_chunk_size, params->chunk_size);
    add_uint_to_json(obj, json_key_position, params->position);
    add_uint_to_json(obj, json_key_max_key_delay, params->max_key_delay);
    add_rate_to_json(obj, json_key_min_bps, params->min_bps);
    add_uint_to_json(obj, json_key_provision_size, params->provision_size);
    add_subobject_to_json(obj, json_key_extensions, params->extensions);

    this->write_json(obj, json_ser_flag::with_length);
}

void message_context::write_qos_parameters(ksnp_stream_qos_params const *params)
{
    if (params == nullptr) {
        // No JSON payload
        write_u16(0);
        return;
    }

    check_qos_range(params->chunk_size);
    check_qos_range(params->min_bps);
    check_qos_range(params->ttl);
    check_qos_range(params->provision_size);

    if (params->chunk_size.type == ksnp_qos_type::KSNP_QOS_RANGE
        && params->chunk_size.range.max > KSNP_MAX_CHUNK_SIZE) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    if (params->chunk_size.type == ksnp_qos_type::KSNP_QOS_LIST) {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
        auto values = std::span{params->chunk_size.list.values, params->chunk_size.list.count};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
        if (std::ranges::any_of(values, [](auto chunk_size) -> bool {
                return chunk_size > KSNP_MAX_CHUNK_SIZE;
            })) {
            throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
        }
    }

    json_ptr main_obj(json_object_new_object());
    auto    *obj = main_obj.get();

    add_qos_u16_to_json(obj, json_key_chunk_size, params->chunk_size);
    add_qos_rate_to_json(obj, json_key_min_bps, params->min_bps);
    add_qos_u32_to_json(obj, json_key_ttl, params->ttl);
    add_qos_u32_to_json(obj, json_key_provision_size, params->provision_size);
    add_subobject_to_json(obj, json_key_extensions, params->extensions);

    this->write_json(obj, json_ser_flag::with_length);
}

[[nodiscard]] auto message_context::want_read() const noexcept -> bool
try {
    if (this->eof) {
        return false;
    }
    auto data = std::span{this->input_data};

    if (this->last_message_len.has_value()) {
        data = data.subspan(*this->last_message_len);
    }

    if (data.size() < KSNP_MSG_HEADER_SIZE) {
        return true;
    }

    auto len_data = data.subspan(2, sizeof(uint16_t));
    auto msg_len  = load_next_u16(len_data);
    return msg_len > data.size();
} catch (...) {
    // Not enough data for message header
    return true;
}

void message_context::read_data(std::span<unsigned char const> data, size_t *read)
{
    free_last_message();
    if (*read == 0) {
        if (this->eof) {
            throw exception(ksnp_error::KSNP_E_INVALID_OPERATION);
        }
        this->eof = true;
        return;
    }

    *read = data.size();
    this->input_data.append(data.data(), read);
    if (*read < data.size() && this->want_read()) {
        // If the buffer is full and no message is ready, report an error
        // as no progress can be made.
        throw exception(ksnp_error::KSNP_E_INSUFFICIENT_BUFFER);
    }
}

[[nodiscard]] auto message_context::want_write() const noexcept -> bool
{
    return !this->output_data.empty();
}

auto message_context::write_data(std::span<unsigned char> data) -> size_t
{
    auto to_copy = std::span(this->output_data);
    if (to_copy.size() > data.size()) {
        to_copy = to_copy.first(data.size());
    }

    std::ranges::copy(to_copy, data.begin());
    this->output_data.consume(to_copy.size());
    return to_copy.size();
}

auto message_context::next_message() -> std::optional<message>
{
    // Clear previous message first, if any
    free_last_message();

    auto data = std::span{this->input_data};

    if (data.size() >= KSNP_MSG_HEADER_SIZE) {
        // Header is complete. Parse it.
        auto msg_type = load_next_u16(data);
        auto msg_len  = load_next_u16(data);
        if (msg_len < KSNP_MSG_HEADER_SIZE) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH);
        }

        if (data.size() >= msg_len - KSNP_MSG_HEADER_SIZE) {
            // Message is complete. Parse message body.
            this->last_message_len = msg_len;
            return this->parse_message(msg_type, data.first(msg_len - KSNP_MSG_HEADER_SIZE));
        }
    }

    if (this->eof && !data.empty()) {
        // Receiving channel has been closed, but incomplete message data
        // is still in the buffer.
        this->input_data.truncate(0);
        throw protocol_exception(ksnp_error_code::KSNP_PROT_E_INCOMPLETE_MSG);
    }

    return std::nullopt;
}

auto message_context::parse_message(uint16_t                 type,  // NOLINT(readability-function-cognitive-complexity)
                                    std::span<uint8_t const> data) -> message
{
    // Partially initialize a message
    ksnp_message msg = {.type = static_cast<ksnp_message_type>(type), .error = {.code = {}}};

    // Create the union member of the message
    switch (msg.type) {
    case ksnp_message_type::KSNP_MSG_ERROR:
        msg.error = ksnp_msg_error{
            .code = static_cast<ksnp_error_code>(load_next_u32(data)),
        };
        break;
    case ksnp_message_type::KSNP_MSG_VERSION:
        msg.version = ksnp_msg_version{
            .minimum_version = static_cast<ksnp_protocol_version>(load_next_u8(data)),
            .maximum_version = static_cast<ksnp_protocol_version>(load_next_u8(data)),
        };
        if (msg.version.minimum_version > msg.version.maximum_version) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
        }
        break;
    case ksnp_message_type::KSNP_MSG_OPEN_STREAM: {
        auto json_params = load_next_json(data, data.size());
        if (!json_params) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_MISSING);
        }
        this->last_message_payload = json_to_stream_params(*json_params);
        msg.open_stream            = ::ksnp_msg_open_stream{
                       .parameters = std::get<stream_open_params>(this->last_message_payload).get_params(),
        };
        break;
    }
    case ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY: {
        msg.open_stream_reply = {
            .code       = load_next_enum<ksnp_status_code>(data),
            .parameters = {.qos = nullptr},
            .message    = nullptr,
        };
        auto json_len    = load_next_u16(data);
        auto json_params = load_next_json(data, json_len);
        if (msg.open_stream_reply.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
            if (!json_params) {
                throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_MISSING);
            }
            this->last_message_payload = json_to_stream_reply_params(*json_params);
            msg.open_stream_reply.parameters.reply =
                std::get<stream_accepted_params>(this->last_message_payload).get_params();
        } else {
            if (json_params) {
                this->last_message_payload = json_to_stream_qos_params(*json_params);
                msg.open_stream_reply.parameters.qos =
                    std::get<stream_qos_params>(this->last_message_payload).get_params();
            }

            // Message is only allowed if code != 0. If there is message
            // data after the JSON parameter for code == 0, we will throw
            // an unexpected data exception.
            msg.open_stream_reply.message = load_next_string(data);
        }
        break;
    }
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM:
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY:
        if (!data.empty()) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH);
        }
        break;
    case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY:
        msg.close_stream_notify = ksnp_msg_close_stream_notify{
            .code    = load_next_enum<ksnp_status_code>(data),
            .message = load_next_string(data),
        };
        break;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM:
        msg.suspend_stream = ksnp_msg_suspend_stream{.timeout = load_next_u32(data)};
        break;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY:
        msg.suspend_stream_reply = {
            .code    = load_next_enum<ksnp_status_code>(data),
            .timeout = load_next_u32(data),
            .message = nullptr,
        };
        // In case of an error, message may be set. If message data is
        // present even though the status code indicates success, we will
        // throw an unexpected extra data exception.
        if (msg.suspend_stream_reply.code != ksnp_status_code::KSNP_STATUS_SUCCESS) {
            msg.suspend_stream_reply.message = load_next_string(data);
        }
        break;
    case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY:
        msg.suspend_stream_notify = {
            .code    = load_next_enum<ksnp_status_code>(data),
            .timeout = load_next_u32(data),
        };
        break;
    case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM:
        msg.keep_alive_stream = {};
        if (data.size() != std::size(msg.keep_alive_stream.key_stream_id)) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH);
        }
        std::ranges::copy(data, std::begin(msg.keep_alive_stream.key_stream_id));
        data = data.subspan(std::size(msg.keep_alive_stream.key_stream_id));
        break;
    case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY:
        msg.keep_alive_stream_reply = ksnp_msg_keep_alive_stream_reply{
            .code    = load_next_enum<ksnp_status_code>(data),
            .message = nullptr,
        };
        // In case of an error, message may be set. If message data is
        // present even though the status code indicates success, we will
        // throw an unexpected extra data exception.
        if (msg.keep_alive_stream_reply.code != ksnp_status_code::KSNP_STATUS_SUCCESS) {
            msg.keep_alive_stream_reply.message = load_next_string(data);
        }
        break;
    case ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY:
        msg.capacity_notify = ksnp_msg_capacity_notify{.additional_capacity = load_next_u32(data)};
        break;
    case ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY: {
        auto data_len = load_next_u16(data);
        if (data.size() < data_len) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH);
        }
        struct ksnp_data key_data = {.data = data.data(), .len = data_len};
        data                      = data.subspan(data_len);
        json_obj payload          = load_next_json(data, data.size());
        if (payload && json_object_get_type(*payload) != json_type_object) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
        }
        this->last_message_payload = key_data_parameters(std::move(payload));
        msg.key_data_notify        = ksnp_msg_key_data_notify{
                   .key_data   = key_data,
                   .parameters = std::get<key_data_parameters>(this->last_message_payload).get_parameters(),
        };
        break;
    }
    case ksnp_message_type::KSNP_MSG_NONE:
    default:
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_TYPE);
    }

    if (!data.empty()) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH, "unexpected extra data");
    }

    // KSNP_MSG_NONE raises an error, so a value exists.
    return *ksnp::message::from_message(msg);
}

void message_context::write_message(  // NOLINT: readability-function-cognitive-complexity
    struct ksnp_message const *msg)
{
    assert(msg != nullptr);
    auto orig_out_len = this->output_data.size();

    try {
        // Write message header, with a placeholder for the message length.
        write_enum(msg->type);
        write_u16(0);

        // Write message body.
        switch (msg->type) {
        case ksnp_message_type::KSNP_MSG_ERROR:
            write_enum(msg->error.code);
            break;
        case ksnp_message_type::KSNP_MSG_VERSION:
            if (msg->version.minimum_version > msg->version.maximum_version) {
                throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
            }
            write_enum(msg->version.minimum_version);
            write_enum(msg->version.maximum_version);
            break;
        case ksnp_message_type::KSNP_MSG_OPEN_STREAM:
            if (msg->open_stream.parameters == nullptr) {
                throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
            }
            write_parameters(msg->open_stream.parameters);
            break;
        case ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY:
            write_enum(msg->open_stream_reply.code);
            if (msg->open_stream_reply.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
                if (msg->open_stream_reply.parameters.reply == nullptr) {
                    throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
                }
                write_reply_parameters(msg->open_stream_reply.parameters.reply);
                if (msg->open_stream_reply.message != nullptr) {
                    throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
                }
            } else {
                write_qos_parameters(msg->open_stream_reply.parameters.qos);
                write_message(msg->open_stream_reply.message);
            }
            break;
        case ksnp_message_type::KSNP_MSG_CLOSE_STREAM:
        case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY:
            break;
        case ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY:
            if (msg->close_stream_notify.code == ksnp_status_code::KSNP_STATUS_SUCCESS
                && msg->close_stream_notify.message != nullptr) {
                throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
            }
            write_enum(msg->close_stream_notify.code);
            write_message(msg->close_stream_notify.message);
            break;
        case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM:
            write_u32(msg->suspend_stream.timeout);
            break;
        case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY:
            if (msg->suspend_stream_reply.code == ksnp_status_code::KSNP_STATUS_SUCCESS
                && msg->suspend_stream_reply.message != nullptr) {
                throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
            }
            write_enum(msg->suspend_stream_reply.code);
            write_u32(msg->suspend_stream_reply.timeout);
            write_message(msg->suspend_stream_reply.message);
            break;
        case ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY:
            write_enum(msg->suspend_stream_reply.code);
            write_u32(msg->suspend_stream_reply.timeout);
            break;
        case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM:
            this->output_data.append_exact(std::begin(msg->keep_alive_stream.key_stream_id),
                                           sizeof(msg->keep_alive_stream.key_stream_id));
            break;
        case ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY:
            if (msg->keep_alive_stream_reply.code == ksnp_status_code::KSNP_STATUS_SUCCESS
                && msg->keep_alive_stream_reply.message != nullptr) {
                throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
            }
            write_enum(msg->keep_alive_stream_reply.code);
            write_message(msg->keep_alive_stream_reply.message);
            break;
        case ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY:
            write_u32(msg->capacity_notify.additional_capacity);
            break;
        case ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY: {
            if (msg->key_data_notify.parameters != nullptr
                && json_object_get_type(msg->key_data_notify.parameters) != json_type_object) {
                throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
            }
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
            std::span key_data(msg->key_data_notify.key_data.data, msg->key_data_notify.key_data.len);
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
            write_u16(static_cast<uint16_t>(key_data.size()));
            this->output_data.append_exact(key_data.data(), key_data.size());
            if (msg->key_data_notify.parameters != nullptr) {
                write_json(msg->key_data_notify.parameters, json_ser_flag::plain);
            }
            break;
        }
        case ksnp_message_type::KSNP_MSG_NONE:
        default:
            throw exception(ksnp_error::KSNP_E_INVALID_MESSAGE_TYPE);
        }

        // Check that message length fits into a uint16_t.
        auto msg_len = this->output_data.size() - orig_out_len;
        if (msg_len > KSNP_MAX_MSG_LEN) {
            throw ksnp::exception(ksnp_error::KSNP_E_SER_MSG_TOO_LARGE);
        }
        // Overwrite the placeholder in the output queue by the message length.
        std::ranges::copy(
            uint_to_be(static_cast<uint16_t>(msg_len)),
            std::span{this->output_data}.subspan(orig_out_len + sizeof(uint16_t), sizeof(uint16_t)).begin());
    } catch (...) {
        // Erase data inserted into output queue, if any, then rethrow.
        this->output_data.truncate(orig_out_len);
        throw;
    }
}

}  // namespace ksnp

struct ksnp_message_context : public ksnp::message_context {
    using ksnp::message_context::message_context;
};

auto ksnp_message_context_create(struct ksnp_message_context **context) noexcept -> ksnp_error
try {
    *context = nullptr;
    *context = new ksnp_message_context();
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_message_context_create_with_buffer(struct ksnp_message_context **context,
                                             struct ksnp_buffer           *read_buffer,
                                             struct ksnp_buffer           *write_buffer) noexcept -> ksnp_error
try {
    *context = nullptr;
    *context = new ksnp_message_context(read_buffer, write_buffer);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

void ksnp_message_context_destroy(struct ksnp_message_context *context) noexcept
{
    delete context;
}

auto ksnp_message_context_want_read(struct ksnp_message_context *ctx) noexcept -> bool
{
    return ctx->want_read();
}

auto ksnp_message_context_read_data(struct ksnp_message_context *ctx, unsigned char const *data, size_t *len) noexcept
    -> ksnp_error
try {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    auto buffer = std::span{data, *len};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    ctx->read_data(buffer, len);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_message_context_next_message(struct ksnp_message_context *ctx,
                                       struct ksnp_message         *message,
                                       ksnp_protocol_error         *protocol_error) noexcept -> ksnp_error
try {
    assert(ctx != nullptr);
    assert(message != nullptr);

    try {
        if (auto next_message = ctx->next_message()) {
            *message = next_message->into_message();
        } else {
            *message = ksnp_message{.type = ksnp_message_type::KSNP_MSG_NONE, .none = 0};
        }

    } catch (ksnp::protocol_exception &e) {
        if (protocol_error != nullptr) {
            protocol_error->code        = e.code();
            protocol_error->description = e.description();
        }
        return ksnp_error::KSNP_E_PROTOCOL_ERROR;
    }
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_message_context_write_message(struct ksnp_message_context *ctx, struct ksnp_message const *msg) noexcept
    -> ksnp_error
try {
    ctx->write_message(msg);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_message_context_want_write(struct ksnp_message_context *ctx) noexcept -> bool
{
    return ctx->want_write();
}

auto ksnp_message_context_write_data(struct ksnp_message_context *ctx, unsigned char *data, size_t *len) noexcept
    -> ksnp_error
try {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    auto buffer = std::span{data, *len};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    auto copied = ctx->write_data(buffer);
    *len        = copied;
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL
