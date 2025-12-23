#include <algorithm>
#include <cassert>
#include <climits>
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
#include <type_traits>
#include <utility>
#include <vector>

#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_tokener.h>
#include <uuid/uuid.h>

#include "helpers.hpp"
#include "ksnp/messages.h"
#include "ksnp/serde.h"
#include "ksnp/types.h"

#ifndef JSON_C_OBJECT_ADD_CONSTANT_KEY
// Support for legacy JSON-C versions.
#define JSON_C_OBJECT_ADD_CONSTANT_KEY JSON_C_OBJECT_KEY_IS_CONSTANT
#endif

using namespace ksnp;

namespace
{

/// @brief Wrapper for ksnp_buffer that makes it act as a Container.
struct buffer {
private:
    ksnp_buffer *buf;

public:
    using element_type    = unsigned char;
    using size_type       = size_t;
    using difference_type = std::ptrdiff_t;

    explicit buffer(ksnp_buffer *buf) : buf(buf)
    {}

    [[nodiscard]] auto data() const noexcept -> unsigned char const *
    {
        return this->buf->data(this->buf);
    }

    [[nodiscard]] auto data() noexcept -> unsigned char *
    {
        return this->buf->data(this->buf);
    }

    [[nodiscard]] auto size() const noexcept -> size_t
    {
        return this->buf->size(this->buf);
    }

    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return this->size() == 0;
    }

    void consume(size_t count) noexcept
    {
        this->buf->consume(this->buf, count);
    }

    void append(unsigned char const *data, size_t len)
    {
        if (auto err = this->buf->append(this->buf, data, len); err != ksnp_error::KSNP_E_NO_ERROR) {
            throw exception(err);
        }
    }

    void truncate(size_t count) noexcept
    {
        this->buf->truncate(this->buf, count);
    }

#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    [[nodiscard]] auto begin() -> unsigned char *
    {
        return this->data();
    }

    [[nodiscard]] auto end() -> unsigned char *
    {
        return this->data() + this->size();
    }

    [[nodiscard]] auto begin() const -> unsigned char const *
    {
        return this->data();
    }

    [[nodiscard]] auto end() const -> unsigned char const *
    {
        return this->data() + this->size();
    }

    [[nodiscard]] auto cbegin() const -> unsigned char const *
    {
        return this->data();
    }

    [[nodiscard]] auto cend() const -> unsigned char const *
    {
        return this->data() + this->size();
    }
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
};

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
constexpr auto uint_from_be(std::span<U8, sizeof(TargetUint)> data) noexcept -> TargetUint
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

template<std::unsigned_integral SourceUint, typename U8 = unsigned char>
constexpr auto uint_to_be(SourceUint val) -> std::array<U8, sizeof(SourceUint)>
{
    constexpr std::size_t COUNT = sizeof(SourceUint);
    constexpr int         BITS  = std::numeric_limits<U8>::digits;

    std::array<U8, COUNT> result{};

    for (size_t i = 0; i < result.size(); i++) {
        result[i] = static_cast<U8>(val >> (BITS * (COUNT - i - 1)));
    }

    return result;
}

template<std::unsigned_integral T>
[[nodiscard]] auto is_all_zero(std::span<T> buf)
{
    for (auto val: buf) {
        if (val != 0) {
            return false;
        }
    }
    return true;
}

using json_obj_deleter = unique_obj<json_object *, json_object_put>;

enum class json_ser_flag : uint8_t {
    plain,
    with_length,
};

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
    auto val = json_object_get_uint64(obj);
    if (!std::in_range<TargetUint>(val)) {
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
[[nodiscard]] constexpr inline bool key_allowed(std::string_view key, string_views... allowed_keys) noexcept
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

[[nodiscard]] auto get_subobject_string(json_object const *obj, zstring_view key) -> char const *
{
    json_object *subobj = nullptr;
    if (json_object_object_get_ex(obj, key.c_str(), &subobj) == 1 && json_object_get_type(subobj) != json_type_string) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
    }
    // If obj has no entry for the given key, subobj will still be nullptr
    // here. The following call is still safe in that case and will return
    // NULL itself.
    return json_object_get_string(subobj);
}

[[nodiscard]] auto json_to_address(json_object const *obj) -> ksnp_address
{
    // First check the type of the subobject, and whether it contains
    // unknown keys.
    check_subobject_allowed_keys(obj, json_key_address_sae, json_key_address_network);

    // Extract address strings.
    return ksnp_address{.sae     = get_subobject_string(obj, json_key_address_sae),
                        .network = get_subobject_string(obj, json_key_address_network)};
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

template<typename QosExpectedValue,
         decltype(std::declval<QosExpectedValue>().range.min) (*ParseObj)(json_object const *)>
[[nodiscard]] auto json_to_qos_range(json_object const *obj) -> QosExpectedValue
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

    auto min_val = ParseObj(min_obj);
    auto max_val = ParseObj(max_obj);

    if (min_val > max_val) {
        throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL);
    }

    return {
        .type = ksnp_qos_type::KSNP_QOS_RANGE, .range = {.min = min_val, .max = max_val}
    };
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

    auto address_obj = json_obj_deleter(check_alloc(json_object_new_object()));
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

auto rate_to_json(struct ksnp_rate rate) -> json_object *
{
    // A numerator of 0 means the field is unset.
    if (rate.bits == 0) {
        return nullptr;
    }

    auto rate_obj = json_obj_deleter(check_alloc(json_object_new_object()));
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
        auto range_obj = json_obj_deleter(check_alloc(json_object_new_object()));
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
        auto array_obj = json_obj_deleter(check_alloc(json_object_new_array_ext(static_cast<int>(list.size()))));
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

}  // namespace

struct ksnp_message_context {
private:
    using qos_lists = std::variant<std::vector<uint16_t>, std::vector<uint32_t>, std::vector<struct ksnp_rate>>;

    // Storage used when no user-provided buffers are used.
    std::optional<vector_buffer> input_storage;
    std::optional<vector_buffer> output_storage;

    buffer input_data;
    buffer output_data;

    std::optional<json_obj_deleter>            parsed_json;
    std::optional<struct ksnp_message>         last_message;
    std::optional<std::string>                 status_message;
    std::optional<ksnp_stream_open_params>     stream_params;
    std::optional<ksnp_stream_accepted_params> stream_params_reply;
    std::optional<ksnp_stream_qos_params>      stream_params_qos;
    std::vector<qos_lists>                     registered_qos_lists;
    bool                                       eof;

    void free_last_message()
    {
        if (!this->last_message.has_value()) {
            return;
        }

        this->last_message.reset();
        this->status_message.reset();
        this->stream_params.reset();
        this->stream_params_reply.reset();
        this->stream_params_qos.reset();
        this->parsed_json.reset();
        this->registered_qos_lists.clear();
        auto msg_len_ser = std::span{this->input_data}.subspan<2, sizeof(uint16_t)>();
        auto msg_len     = uint_from_be<uint16_t>(msg_len_ser);
        this->input_data.consume(msg_len);
    }

    auto load_next_string(std::span<uint8_t const> &data) -> char const *
    {
        if (data.empty()) {
            this->status_message = std::nullopt;
            return nullptr;
        }
        this->status_message.emplace(data.begin(), data.end());
        data = data.subspan(data.size());
        return this->status_message->c_str();
    }

    auto load_next_json(std::span<uint8_t const> &data, size_t json_len) -> json_object *
    {
        this->parsed_json.reset();

        if (json_len > data.size() || json_len > INT_MAX) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_LENGTH,
                                           "JSON length exceeds message length");
        }

        if (data.empty()) {
            return nullptr;
        }

        // Wrap the tokener in a unique_obj so it is properly freed in case of an
        // exception.
        unique_obj<json_tokener *, json_tokener_free> tok(json_tokener_new());

        auto const *data_ptr = data.data();
        auto       *obj =
            json_tokener_parse_ex(tok.get(), reinterpret_cast<char const *>(data_ptr), static_cast<int>(json_len));
        if (obj == nullptr) {
            this->status_message = json_tokener_error_desc(json_tokener_get_error(tok.get()));
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON, this->status_message->c_str());
        }

        // Wrap the JSON object in a unique_ptr so it automatically frees its
        // data when it goes out of scope. If the function is successful, store
        // this object in the message context to extend the lifetime of all
        // pointers into the JSON data.
        json_obj_deleter raii_obj(obj);

        // After the parsed JSON object, only whitespace is allowed within the
        // JSON field of the message (as defined by `json_len`).
        // Note that the JSON library only parses up to `json_len` bytes, so
        // `parsed_len <= json_len`.
        auto parsed_len = json_tokener_get_parse_end(tok.get());
        if (!std::ranges::all_of(data.subspan(parsed_len, json_len - parsed_len), ::isspace)) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_LENGTH,
                                           "extra data after JSON object");
        }

        if (json_object_is_type(obj, json_type_object) == 0) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE,
                                           "unexpected top level object type");
        }

        this->parsed_json = std::move(raii_obj);
        data              = data.subspan(json_len);

        return this->parsed_json->get();
    }

    template<std::unsigned_integral T>
    void write_uint(T val)
    {
        auto bytes = uint_to_be(val);
        this->output_data.append(bytes.data(), bytes.size());
    }

    void write_u16(uint16_t val)
    {
        write_uint(val);
    }

    void write_u32(uint32_t val)
    {
        write_uint(val);
    }

    template<typename T>
    void write_enum(T val)
    {
        write_uint(static_cast<typename std::underlying_type_t<T>>(val));
    }

    void write_json(json_object *obj, json_ser_flag flag)
    {
        size_t      json_len;
        auto const *json_ptr = check_alloc(json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN, &json_len));
        std::string_view json(json_ptr, json_len);
        if (!std::in_range<uint16_t>(json_len)) {
            throw exception(ksnp_error::KSNP_E_SER_JSON_TOO_LARGE);
        }
        if (flag == json_ser_flag::with_length) {
            this->write_u16(static_cast<uint16_t>(json_len));
        }
        this->output_data.append(reinterpret_cast<unsigned char const *>(json.data()), json.size());
    }

    void write_message(char const *msg)
    {
        if (msg == nullptr) {
            return;
        }
        std::string_view msg_view(msg);
        this->output_data.append(reinterpret_cast<unsigned char const *>(msg_view.data()), msg_view.size());
    }

    void write_parameters(ksnp_stream_open_params const *params)
    {
        json_obj_deleter main_obj(json_object_new_object());
        auto            *obj = main_obj.get();

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

    void write_reply_parameters(ksnp_stream_accepted_params const *params)
    {
        json_obj_deleter main_obj(json_object_new_object());
        auto            *obj = main_obj.get();

        add_stream_id_to_json(obj, json_key_ksid, {params->stream_id});
        add_uint_to_json(obj, json_key_chunk_size, params->chunk_size);
        add_uint_to_json(obj, json_key_position, params->position);
        add_uint_to_json(obj, json_key_max_key_delay, params->max_key_delay);
        add_rate_to_json(obj, json_key_min_bps, params->min_bps);
        add_uint_to_json(obj, json_key_provision_size, params->provision_size);
        add_subobject_to_json(obj, json_key_extensions, params->extensions);

        this->write_json(obj, json_ser_flag::with_length);
    }

    void write_qos_parameters(ksnp_stream_qos_params const *params)
    {
        if (params == nullptr) {
            // No JSON payload
            write_u16(0);
            return;
        }

        json_obj_deleter main_obj(json_object_new_object());
        auto            *obj = main_obj.get();

        add_qos_u16_to_json(obj, json_key_chunk_size, params->chunk_size);
        add_qos_rate_to_json(obj, json_key_min_bps, params->min_bps);
        add_qos_u32_to_json(obj, json_key_ttl, params->ttl);
        add_qos_u32_to_json(obj, json_key_provision_size, params->provision_size);
        add_subobject_to_json(obj, json_key_extensions, params->extensions);

        this->write_json(obj, json_ser_flag::with_length);
    }

    [[nodiscard]] auto json_to_stream_params(json_object *json) -> ksnp_stream_open_params const *
    {
        struct ksnp_stream_open_params params{};

        auto end_iter = json_object_iter_end(json);
        for (auto it = json_object_iter_begin(json); json_object_iter_equal(&it, &end_iter) == 0;
             json_object_iter_next(&it)) {
            std::string_view name  = json_object_iter_peek_name(&it);
            auto            *value = json_object_iter_peek_value(&it);
            if (name == json_key_ksid) {
                json_to_stream_id(value, params.stream_id);
            } else if (name == json_key_source) {
                params.source = json_to_address(value);
            } else if (name == json_key_destination) {
                params.destination = json_to_address(value);
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
                params.extensions = value;
            } else if (name == json_key_required_extensions) {
                params.required_extensions = value;
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

        this->stream_params = params;
        return &this->stream_params.value();
    }

    [[nodiscard]] auto json_to_stream_reply_params(json_object *json) -> ksnp_stream_accepted_params const *
    {
        struct ksnp_stream_accepted_params params{};
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
                params.extensions = value;
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

        this->stream_params_reply = params;
        return &this->stream_params_reply.value();
    }

    template<typename QosExpectedValue,
             typename TargetType = decltype(std::declval<QosExpectedValue>().range.min),
             TargetType (*ParseObj)(json_object const *)>
    [[nodiscard]] auto register_qos_list(json_object const *obj) -> QosExpectedValue
    {
        auto count = json_object_array_length(obj);
        if (count == 0) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL, "empty QoS expected array");
        }

        std::vector<TargetType> qos_list;
        qos_list.reserve(count);
        for (size_t i = 0; i < count; i++) {
            auto *entry = json_object_array_get_idx(obj, i);
            qos_list.push_back(ParseObj(entry));
        }

        this->registered_qos_lists.push_back(std::move(qos_list));
        auto &reg_list = get<decltype(qos_list)>(this->registered_qos_lists.back());

        return {
            .type = ksnp_qos_type::KSNP_QOS_LIST, .list = {.values = reg_list.data(), .count = reg_list.size()}
        };
    }

    template<typename QosExpectedValue,
             typename TargetType = decltype(std::declval<QosExpectedValue>().range.min),
             TargetType (*ParseObj)(json_object const *)>
    [[nodiscard]] auto json_to_qos(json_object const *obj) -> QosExpectedValue
    {
        switch (json_object_get_type(obj)) {
        case json_type_null:
            return {.type = ksnp_qos_type::KSNP_QOS_NULL, .none = 0};
        case json_type_object:
            return json_to_qos_range<QosExpectedValue, ParseObj>(obj);
        case json_type_array:
            return this->register_qos_list<QosExpectedValue, TargetType, ParseObj>(obj);
        default:
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE);
        }
    }

    [[nodiscard]] auto json_to_qos_u16(json_object const *obj) -> ksnp_qos_u16
    {
        return json_to_qos<ksnp_qos_u16, uint16_t, json_to_u16>(obj);
    }

    [[nodiscard]] auto json_to_qos_u32(json_object const *obj) -> ksnp_qos_u32
    {
        return json_to_qos<ksnp_qos_u32, uint32_t, json_to_u32>(obj);
    }

    [[nodiscard]] auto json_to_qos_rate(json_object const *obj) -> ksnp_qos_rate
    {
        return json_to_qos<ksnp_qos_rate, struct ksnp_rate, json_to_rate>(obj);
    }

    [[nodiscard]] auto json_to_stream_qos_params(json_object *json) -> ksnp_stream_qos_params const *
    {
        struct ksnp_stream_qos_params params{
            .chunk_size     = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
            .min_bps        = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
            .ttl            = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
            .provision_size = {.type = ksnp_qos_type::KSNP_QOS_NONE, .none = 0},
            .extensions     = nullptr,
        };

        auto end_iter = json_object_iter_end(json);
        for (auto it = json_object_iter_begin(json); json_object_iter_equal(&it, &end_iter) == 0;
             json_object_iter_next(&it)) {
            std::string_view name  = json_object_iter_peek_name(&it);
            auto            *value = json_object_iter_peek_value(&it);

            if (name == json_key_chunk_size) {
                params.chunk_size = json_to_qos_u16(value);
            } else if (name == json_key_min_bps) {
                params.min_bps = json_to_qos_rate(value);
            } else if (name == json_key_ttl) {
                params.ttl = json_to_qos_u32(value);
            } else if (name == json_key_provision_size) {
                params.provision_size = json_to_qos_u32(value);
            } else if (name == json_key_extensions) {
                params.extensions = value;
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

        this->stream_params_qos = params;
        return &this->stream_params_qos.value();
    }

public:
    ksnp_message_context()
        : input_storage(vector_buffer())
        , output_storage(vector_buffer())
        , input_data(this->input_storage->ksnp_buffer_ptr())
        , output_data(this->output_storage->ksnp_buffer_ptr())
        , eof(false)
    {}

    ksnp_message_context(ksnp_buffer *read_buffer,  // NOLINT: bugprone-easily-swappable-parameters
                         ksnp_buffer *write_buffer)
        : input_data(read_buffer)
        , output_data(write_buffer)
        , eof(false)
    {}

    [[nodiscard]] auto want_read() const noexcept -> bool
    try {
        if (this->eof) {
            return false;
        }
        auto data = std::span{this->input_data};

        if (this->last_message.has_value()) {
            auto len_data = data.subspan(2, sizeof(uint16_t));
            data          = data.subspan(load_next_u16(len_data));
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

    auto read_data(std::span<unsigned char const> data, size_t *read) -> ksnp_error
    {
        free_last_message();
        if (*read == 0) {
            if (this->eof) {
                return ksnp_error::KSNP_E_INVALID_OPERATION;
            }
            this->eof = true;
            return ksnp_error::KSNP_E_NO_ERROR;
        }

        this->input_data.append(data.data(), data.size());
        *read = data.size();
        return ksnp_error::KSNP_E_NO_ERROR;
    }

    [[nodiscard]] auto want_write() const noexcept -> bool
    {
        return !this->output_data.empty();
    }

    auto write_data(std::span<unsigned char> data) -> size_t
    {
        auto to_copy =
            static_cast<decltype(this->output_data)::difference_type>(std::min(this->output_data.size(), data.size()));

        std::copy_n(this->output_data.begin(), to_copy, data.begin());
        this->output_data.consume(to_copy);
        return static_cast<size_t>(to_copy);
    }

    auto next_message(struct ksnp_message const **msg, ksnp_protocol_error *protocol_error) -> ksnp_error
    try {
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
                auto err = this->parse_message(msg_type, data.first(msg_len - KSNP_MSG_HEADER_SIZE));
                if (err == ksnp_error::KSNP_E_NO_ERROR) {
                    // Message parsed successfully, set output
                    *msg = &(*this->last_message);
                }
                return err;
            }
        }

        *msg = nullptr;
        if (this->eof && !data.empty()) {
            // Receiving channel has been closed, but incomplete message data
            // is still in the buffer.
            this->input_data.truncate(0);
            if (protocol_error != nullptr) {
                *protocol_error =
                    ksnp_protocol_error{.code = ksnp_error_code::KSNP_PROT_E_INCOMPLETE_MSG, .description = nullptr};
            }
            return ksnp_error::KSNP_E_PROTOCOL_ERROR;
        }
        return ksnp_error::KSNP_E_NO_ERROR;
    } catch (ksnp::protocol_exception &e) {
        if (protocol_error != nullptr) {
            *protocol_error = ksnp_protocol_error{.code = e.code(), .description = e.what()};
        }
        return ksnp_error::KSNP_E_PROTOCOL_ERROR;
    }

    auto parse_message(uint16_t type, std::span<uint8_t const> data) -> ksnp_error
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
            auto *json_params = load_next_json(data, data.size());
            if (json_params == nullptr) {
                throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_MISSING);
            }
            msg.open_stream = ::ksnp_msg_open_stream{
                .parameters = json_to_stream_params(json_params),
            };
            break;
        }
        case ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY: {
            msg.open_stream_reply = {
                .code       = load_next_enum<ksnp_status_code>(data),
                .parameters = {.qos = nullptr},
                .message    = nullptr,
            };
            auto  json_len    = load_next_u16(data);
            auto *json_params = load_next_json(data, json_len);
            if (msg.open_stream_reply.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
                if (json_params == nullptr) {
                    throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_JSON_MISSING);
                }
                msg.open_stream_reply.parameters.reply = json_to_stream_reply_params(json_params);
            } else {
                msg.open_stream_reply.parameters.qos =
                    json_params != nullptr ? json_to_stream_qos_params(json_params) : nullptr;
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
            auto *json_params         = load_next_json(data, data.size());
            msg.key_data_notify       = ksnp_msg_key_data_notify{
                      .key_data   = key_data,
                      .parameters = json_params,
            };
            break;
        }
        default:
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_TYPE);
        }

        if (!data.empty()) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH, "unexpected extra data");
        }

        this->last_message = msg;
        return ksnp_error::KSNP_E_NO_ERROR;
    }

    auto write_message(struct ksnp_message const *msg)  // NOLINT: readability-function-cognitive-complexity
        -> ksnp_error

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
                this->output_data.append(std::begin(msg->keep_alive_stream.key_stream_id),
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
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
                std::span key_data(msg->key_data_notify.key_data.data, msg->key_data_notify.key_data.len);
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
                write_u16(static_cast<uint16_t>(key_data.size()));
                this->output_data.append(key_data.data(), key_data.size());
                if (msg->key_data_notify.parameters != nullptr) {
                    write_json(msg->key_data_notify.parameters, json_ser_flag::plain);
                }
                break;
            }
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

        return ksnp_error::KSNP_E_NO_ERROR;
    }
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
    return ctx->read_data(buffer, len);
}
CATCH_ALL

auto ksnp_message_context_next_message(struct ksnp_message_context *ctx,
                                       struct ksnp_message const  **msg,
                                       ksnp_protocol_error         *protocol_error) noexcept -> ksnp_error
try {
    assert(ctx != nullptr);
    assert(msg != nullptr);

    return ctx->next_message(msg, protocol_error);
}
CATCH_ALL

auto ksnp_message_context_write_message(struct ksnp_message_context *ctx, struct ksnp_message const *msg) noexcept
    -> ksnp_error
try {
    return ctx->write_message(msg);
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
