#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <json-c/json_object.h>

#include "helpers.hpp"
#include "ksnp/serde.h"

namespace ksnp
{

/// @brief Wrapper for ksnp_buffer that makes it act as a Container.
struct buffer {
private:
    ksnp_buffer *buf;

public:
    using element_type    = unsigned char;
    using size_type       = std::size_t;
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

    [[nodiscard]] auto size() const noexcept -> std::size_t
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

    void append_exact(unsigned char const *data, size_t len)
    {
        auto written = len;
        if (auto err = this->buf->append(this->buf, data, &written); err != ksnp_error::KSNP_E_NO_ERROR) {
            throw exception(err);
        }
        if (len != written) {
            throw exception(ksnp_error::KSNP_E_INSUFFICIENT_BUFFER);
        }
    }

    void append(unsigned char const *data, size_t *len)
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
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
};

using json_ptr = unique_obj<json_object *, json_object_put>;

class json_obj : json_ptr
{

public:
    json_obj() = default;

    explicit json_obj(json_object *obj) : json_ptr(json_object_get(ensure_object(obj)))
    {}

    using json_ptr::operator*;
    using json_ptr::operator->;
    using json_ptr::operator bool;

private:
    static auto ensure_object(json_object *obj) -> json_object *
    {
        if (json_object_is_type(obj, json_type_object) == 0) {
            throw ksnp::protocol_exception(ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE, "expected JSON object");
        }
        return obj;
    }
};

class stream_address
{
private:
    json_ptr     sae;
    json_ptr     network;
    ksnp_address address;

public:
    stream_address() : address{.sae = nullptr, .network = nullptr}
    {}

    stream_address(json_ptr sae, json_ptr network)
        : sae(std::move(sae))
        , network(std::move(network))
        , address{.sae = json_object_get_string(*this->sae), .network = json_object_get_string(*this->network)}
    {}

    [[nodiscard]] auto get_address() const -> ksnp_address const &
    {
        return this->address;
    }
};

class stream_open_params
{
private:
    ksnp_stream_open_params params;
    stream_address          source;
    stream_address          destination;
    json_obj                extensions;
    json_obj                required_extensions;

public:
    stream_open_params(ksnp_stream_open_params params,
                       stream_address          source,
                       stream_address          destination,
                       json_obj                extensions,
                       json_obj                required_extensions)
        : params(params)
        , source(std::move(source))
        , destination(std::move(destination))
        , extensions(std::move(extensions))
        , required_extensions(std::move(required_extensions))
    {}

    [[nodiscard]] auto get_params() -> ksnp_stream_open_params *
    {
        return &this->params;
    }
};

class stream_accepted_params
{
private:
    ksnp_stream_accepted_params params;
    json_obj                    extensions;

public:
    stream_accepted_params(ksnp_stream_accepted_params params, json_obj extensions)
        : params(params)
        , extensions(std::move(extensions))
    {}

    [[nodiscard]] auto get_params() -> ksnp_stream_accepted_params *
    {
        return &this->params;
    }
};

class stream_qos_params
{
private:
    ksnp_stream_qos_params params;
    std::vector<uint16_t>  chunk_list;
    std::vector<ksnp_rate> min_bps_list;
    std::vector<uint32_t>  ttl_list;
    std::vector<uint32_t>  provision_size_list;
    json_obj               extensions;

public:
    stream_qos_params(ksnp_stream_qos_params params,
                      std::vector<uint16_t>  chunk_list,
                      std::vector<ksnp_rate> min_bps_list,
                      std::vector<uint32_t>  ttl_list,
                      std::vector<uint32_t>  provision_size_list,
                      json_obj               extensions)
        : params(params)
        , chunk_list(std::move(chunk_list))
        , min_bps_list(std::move(min_bps_list))
        , ttl_list(std::move(ttl_list))
        , provision_size_list(std::move(provision_size_list))
        , extensions(std::move(extensions))
    {}

    [[nodiscard]] auto get_params() -> ksnp_stream_qos_params *
    {
        return &this->params;
    }
};

class key_data_parameters
{
private:
    json_obj parameters;

public:
    explicit key_data_parameters(json_obj parameters) : parameters(std::move(parameters))
    {}

    [[nodiscard]] auto get_parameters() -> json_object *
    {
        return *this->parameters;
    }
};

template<std::unsigned_integral SourceUint, typename U8 = unsigned char>
[[nodiscard]] constexpr auto uint_to_be(SourceUint val) -> std::array<U8, sizeof(SourceUint)>
{
    constexpr std::size_t COUNT = sizeof(SourceUint);
    constexpr int         BITS  = std::numeric_limits<U8>::digits;

    std::array<U8, COUNT> result{};

    for (size_t i = 0; i < result.size(); i++) {
        result[i] = static_cast<U8>(val >> (BITS * (COUNT - i - 1)));
    }

    return result;
}

struct message_context {
private:
    using message_payload = std::
        variant<std::monostate, stream_open_params, stream_accepted_params, stream_qos_params, key_data_parameters>;

    enum class json_ser_flag : std::uint8_t {
        plain,
        with_length,
    };

    // Storage used when no user-provided buffers are used.
    std::optional<vector_buffer> input_storage;
    std::optional<vector_buffer> output_storage;

    buffer input_data;
    buffer output_data;

    std::optional<std::uint16_t> last_message_len;
    std::string                  status_message;
    message_payload              last_message_payload;
    bool                         eof;

    void free_last_message();

    auto load_next_string(std::span<std::uint8_t const> &data) -> char const *;

    auto load_next_json(std::span<std::uint8_t const> &data, std::size_t json_len) -> json_obj;

    template<std::unsigned_integral T>
    void write_uint(T val)
    {
        auto bytes = uint_to_be(val);
        this->output_data.append_exact(bytes.data(), bytes.size());
    }

    void write_u16(std::uint16_t val)
    {
        write_uint(val);
    }

    void write_u32(std::uint32_t val)
    {
        write_uint(val);
    }

    template<typename T>
    void write_enum(T val)
    {
        write_uint(static_cast<typename std::underlying_type_t<T>>(val));
    }

    void write_json(json_object *obj, json_ser_flag flag);

    void write_message(char const *msg);

    void write_parameters(ksnp_stream_open_params const *params);

    void write_reply_parameters(ksnp_stream_accepted_params const *params);

    void write_qos_parameters(ksnp_stream_qos_params const *params);

public:
    message_context()
        : input_storage(vector_buffer())
        , output_storage(vector_buffer())
        , input_data(this->input_storage->as_buffer_ptr())
        , output_data(this->output_storage->as_buffer_ptr())
        , eof(false)
    {}

    message_context(ksnp_buffer *read_buffer,  // NOLINT: bugprone-easily-swappable-parameters
                    ksnp_buffer *write_buffer)
        : input_data(read_buffer)
        , output_data(write_buffer)
        , eof(false)
    {}

    [[nodiscard]] auto want_read() const noexcept -> bool;

    void read_data(std::span<unsigned char const> data, size_t *read);

    [[nodiscard]] auto want_write() const noexcept -> bool;

    auto write_data(std::span<unsigned char> data) -> size_t;

    auto next_message() -> std::optional<message>;

    auto parse_message(std::uint16_t type, std::span<unsigned char const> data) -> message;

    void write_message(struct ksnp_message const *msg);
};

}  // namespace ksnp
