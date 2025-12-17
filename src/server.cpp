/*
Single connection context
*/

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>

#include <uuid/uuid.h>

#include "helpers.hpp"
#include "ksnp/messages.h"
#include "ksnp/serde.h"
#include "ksnp/server.h"
#include "ksnp/types.h"
#include "server.hpp"

using namespace ksnp;

ksnp_server::ksnp_server(ksnp_message_context *connection)
    : connection(connection)
    , current_stream(nullptr)
    , client_capacity(0)
    , stream_state(stream_state::closed)
    , in_shutdown(false)
{
    this->push_message(::ksnp_msg_version{.minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                                          .maximum_version = ksnp_protocol_version::PROTOCOL_V1});
}

auto ksnp_server::want_read() const noexcept -> bool
{
    if (this->stream_state == stream_state::error) {
        return false;
    }
    return ::ksnp_message_context_want_read(this->connection);
}

auto ksnp_server::read_data(std::span<uint8_t const> data) -> size_t
{
    size_t len = data.size();
    if (auto res = ::ksnp_message_context_read_data(this->connection, data.data(), &len);
        res != ksnp_error::KSNP_E_NO_ERROR) {
        throw ksnp::exception(res);
    }
    return len;
}

auto ksnp_server::want_write() const noexcept -> bool
{
    return (::ksnp_message_context_want_write(this->connection)
            || (this->current_stream && this->client_capacity >= this->current_stream->chunk_size
                && this->current_stream->has_chunk_available(*this->current_stream)));
}

auto ksnp_server::write_data(std::span<uint8_t> data) -> size_t
{
    auto len = data.size();
    if (auto res = ::ksnp_message_context_write_data(this->connection, data.data(), &len);
        res != ksnp_error::KSNP_E_NO_ERROR) {
        throw ksnp::exception(res);
    }
    auto remaining_data = data.subspan(len);
    if (this->current_stream && remaining_data.size() > (this->current_stream->chunk_size + KSNP_MSG_HEADER_SIZE)
        && !::ksnp_message_context_want_write(this->connection)
        && this->client_capacity >= this->current_stream->chunk_size
        && this->current_stream->has_chunk_available(*this->current_stream)) {
        auto available = std::min(remaining_data.size(), KSNP_MAX_MSG_LEN) - KSNP_MSG_HEADER_SIZE;
        auto max_count =
            std::min(static_cast<uint32_t>(available), this->client_capacity) / this->current_stream->chunk_size;
        ::ksnp_data chunk_data = {};
        if (auto res =
                this->current_stream->next_chunk(*this->current_stream, &chunk_data, static_cast<uint16_t>(max_count));
            res != ksnp_error::KSNP_E_NO_ERROR) {
            throw ksnp::exception(res);
        }
        if (chunk_data.len > 0) {
            if (chunk_data.len > (static_cast<size_t>(max_count * this->current_stream->chunk_size))) {
                throw ksnp::exception(ksnp_error::KSNP_E_KEY_DATA_TOO_LARGE);
            }
            this->push_message(ksnp_msg_key_data_notify{.key_data = chunk_data, .parameters = nullptr});
            this->client_capacity -= chunk_data.len;
        }
        auto remaining_len = remaining_data.size();
        if (auto res = ::ksnp_message_context_write_data(this->connection, remaining_data.data(), &remaining_len);
            res != ksnp_error::KSNP_E_NO_ERROR) {
            throw ksnp::exception(res);
        }
        len += remaining_len;
    }
    return len;
}

auto ksnp_server::next_event() -> std::optional<server_event>
{
    if (this->current_action) {
        // An action should have been performed.
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }

    while (true) {
        ksnp_message const *msg{};
        ksnp_protocol_error protocol_error{};
        auto                res = ::ksnp_message_context_next_message(this->connection, &msg, &protocol_error);
        if (res == ksnp_error::KSNP_E_NO_ERROR) {
            if (msg == nullptr) {
                return std::nullopt;
            }
            if (auto event = this->process_message(*msg); event.has_value()) {
                return event;
            }
        } else if (res == ksnp_error::KSNP_E_PROTOCOL_ERROR) {
            this->stream_state = stream_state::error;
            return ksnp_server_event_error{
                .code        = protocol_error.code,
                .description = protocol_error.description,
                .stream      = this->current_stream.release(),
            };
        } else {
            throw ksnp::exception(res);
        }
    }
}

auto ksnp_server::process_message(ksnp_message const &msg) -> std::optional<server_event>
{
    if (this->stream_state == stream_state::error) {
        return std::nullopt;
    }

    if (!this->version) {
        overloads version_msg_visitor{[this](::ksnp_msg_error msg) -> std::optional<server_event> {
                                          this->stream_state = stream_state::error;
                                          return ksnp_server_event_error{.code        = msg.code,
                                                                         .description = nullptr,
                                                                         .stream      = this->current_stream.release()};
                                      },
                                      [this](::ksnp_msg_version msg) -> std::optional<server_event> {
                                          if (msg.minimum_version != ksnp_protocol_version::PROTOCOL_V1
                                              || msg.maximum_version < ksnp_protocol_version::PROTOCOL_V1) {
                                              throw version_exception();
                                          }
                                          this->version = ksnp_protocol_version::PROTOCOL_V1;
                                          return ::ksnp_server_event_handshake{
                                              .protocol = *this->version,
                                          };
                                      },
                                      [this](auto) -> std::optional<server_event> {
                                          return this->on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                                      }};
        return std::visit(version_msg_visitor, into_message(msg));
    }

    overloads msg_visitor{[this](::ksnp_msg_error msg) -> std::optional<server_event> {
                              this->stream_state = stream_state::error;
                              return ksnp_server_event_error{
                                  .code        = msg.code,
                                  .description = nullptr,
                                  .stream      = this->current_stream.release(),
                              };
                          },
                          [this](::ksnp_msg_open_stream msg) -> std::optional<server_event> {
                              if (this->stream_state != stream_state::closed) {
                                  return this->on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              }
                              this->client_capacity = msg.parameters->capacity;
                              if (!this->in_shutdown) {
                                  this->current_action = action::opening;
                              }
                              return ::ksnp_server_event_open_stream{
                                  .parameters = msg.parameters,
                              };
                          },
                          [this](::ksnp_msg_close_stream) -> std::optional<server_event> {
                              switch (this->stream_state) {
                              case stream_state::closed:
                                  return this->on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::open:
                                  this->stream_state = stream_state::closed;
                                  this->push_message(ksnp_msg_close_stream_reply{});
                                  return ::ksnp_server_event_close_stream{
                                      .stream = this->current_stream.release(),
                                  };
                              case stream_state::suspending:
                              case stream_state::closing:
                                  this->stream_state = stream_state::closed;
                                  return std::nullopt;
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [this](::ksnp_msg_suspend_stream msg) -> std::optional<server_event> {
                              switch (this->stream_state) {
                              case stream_state::closed:
                                  return this->on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::open:
                                  if (!this->in_shutdown) {
                                      this->current_action = action::suspending;
                                  }
                                  return ::ksnp_server_event_suspend_stream{
                                      .timeout = msg.timeout,
                                  };
                              case stream_state::suspending:
                                  this->stream_state = stream_state::closed;
                                  return std::nullopt;
                              case stream_state::closing:
                                  return std::nullopt;
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [](::ksnp_msg_keep_alive_stream msg) -> std::optional<server_event> {
                              auto event = ::ksnp_server_event_keep_alive{};
                              std::ranges::copy(msg.key_stream_id, std::begin(event.stream_id));
                              return event;
                          },
                          [this](::ksnp_msg_capacity_notify msg) -> std::optional<server_event> {
                              switch (this->stream_state) {
                              case stream_state::closed:
                                  return this->on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::open:
                                  if (std::numeric_limits<uint32_t>::max() - this->client_capacity
                                      < msg.additional_capacity) {
                                      return this->on_error(ksnp_error_code::KSNP_PROT_E_EXCESSIVE_CAPACITY);
                                  }
                                  this->client_capacity += msg.additional_capacity;
                                  return ::ksnp_server_event_new_capacity{
                                      .additional_capacity = msg.additional_capacity,
                                      .current_capacity    = this->client_capacity,
                                  };
                              case stream_state::suspending:
                              case stream_state::closing:
                                  return std::nullopt;
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [this](auto) -> std::optional<server_event> {
                              return this->on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                          }};

    return std::visit(msg_visitor, into_message(msg));
}

void ksnp_server::open_stream_ok(ksnp_stream *stream, struct ksnp_stream_accepted_params const *params)
{
    if (this->current_stream || this->current_action != action::opening) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    if (stream->chunk_size > KSNP_MAX_CHUNK_SIZE) {
        throw ksnp::exception(ksnp_error::KSNP_E_CHUNK_SIZE_TOO_LARGE);
    }
    this->push_message(ksnp_msg_open_stream_reply{
        .code = ksnp_status_code::KSNP_STATUS_SUCCESS,
        .parameters{.reply = params},
        .message = nullptr,
    });
    this->current_action = std::nullopt;
    this->stream_state   = stream_state::open;
    this->current_stream = stream;
}

void ksnp_server::open_stream_fail(ksnp_status_code                     reason,
                                   struct ksnp_stream_qos_params const *params,
                                   char const                          *message)
{
    if (this->current_stream || this->current_action != action::opening) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    if (reason == ksnp_status_code::KSNP_STATUS_SUCCESS) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    this->push_message(ksnp_msg_open_stream_reply{
        .code       = reason,
        .parameters = {.qos = params},
        .message    = message,
    });
    this->client_capacity = 0;
    this->current_action  = std::nullopt;
}

auto ksnp_server::close_stream() -> ksnp_stream *
{
    if (this->stream_state != stream_state::open || this->current_action) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }

    this->push_message(ksnp_msg_close_stream_notify{
        .code    = ksnp_status_code::KSNP_STATUS_SUCCESS,
        .message = nullptr,
    });
    this->stream_state = stream_state::closing;
    return this->current_stream.release();
}

auto ksnp_server::suspend_stream_ok(uint32_t timeout) -> ksnp_stream *
{
    if (this->stream_state != stream_state::open
        || (this->current_action && this->current_action != action::suspending)) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }

    if (this->current_action) {
        this->push_message(ksnp_msg_suspend_stream_notify{
            .code    = ksnp_status_code::KSNP_STATUS_SUCCESS,
            .timeout = timeout,
        });
        this->current_action = std::nullopt;
        this->stream_state   = stream_state::suspending;
    } else {
        this->push_message(ksnp_msg_suspend_stream_reply{
            .code    = ksnp_status_code::KSNP_STATUS_SUCCESS,
            .timeout = timeout,
            .message = nullptr,
        });
    }

    return this->current_stream.release();
}

void ksnp_server::suspend_stream_fail(ksnp_status_code reason, char const *message)
{
    if (this->stream_state != stream_state::open || this->current_action != action::suspending) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    if (reason == ksnp_status_code::KSNP_STATUS_SUCCESS) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    this->push_message(ksnp_msg_suspend_stream_reply{
        .code    = reason,
        .timeout = 0,
        .message = message,
    });
    this->current_action = std::nullopt;
}

void ksnp_server::keep_alive_ok()
{
    if (this->current_action != action::keep_alive) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }

    this->push_message(ksnp_msg_keep_alive_stream_reply{
        .code    = ksnp_status_code::KSNP_STATUS_SUCCESS,
        .message = nullptr,
    });
    this->current_action = std::nullopt;
}

void ksnp_server::keep_alive_fail(ksnp_status_code reason, char const *message)
{
    if (this->current_action != action::keep_alive) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    if (reason == ksnp_status_code::KSNP_STATUS_SUCCESS) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    this->push_message(ksnp_msg_keep_alive_stream_reply{
        .code    = reason,
        .message = message,
    });
    this->current_action = std::nullopt;
}

void ksnp_server::close_connection(ksnp_close_direction dir)
{
    bool close_read  = dir == ksnp_close_direction::KSNP_CLOSE_READ || dir == ksnp_close_direction::KSNP_CLOSE_BOTH;
    bool close_write = dir == ksnp_close_direction::KSNP_CLOSE_WRITE || dir == ksnp_close_direction::KSNP_CLOSE_BOTH;
    if (!close_read && !close_write) {
        throw exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    if (close_read) {
        size_t len = 0;
        if (auto res = ::ksnp_message_context_read_data(this->connection, nullptr, &len);
            res != ksnp_error::KSNP_E_NO_ERROR) {
            throw ksnp::exception(res);
        }
    }

    if (close_write) {
        if (this->in_shutdown) {
            throw exception(ksnp_error::KSNP_E_INVALID_OPERATION);
        }
        this->in_shutdown    = true;
        this->current_action = std::nullopt;
    }
}

void ksnp_server::push_message(message_t const msg)
{
    if (this->in_shutdown) {
        return;
    }
    auto c_msg = into_message(msg);
    if (auto res = ::ksnp_message_context_write_message(this->connection, &c_msg); res != ksnp_error::KSNP_E_NO_ERROR) {
        throw ksnp::exception(res);
    }
}

auto ksnp_server::on_error(ksnp_error_code err) -> server_event
{
    if (this->stream_state != stream_state::error) {
        this->push_message(ksnp_msg_error{.code = err});
    }
    this->stream_state = stream_state::error;
    return ksnp_server_event_error{
        .code        = err,
        .description = nullptr,
        .stream      = this->current_stream.release(),
    };
}

void simple_stream::add_key_data(std::span<uint8_t const> data)
{
    if (this->prev_read > 0) {
        this->provisioned_data.erase(this->provisioned_data.begin(),
                                     this->provisioned_data.begin() + static_cast<diff_t>(this->prev_read));
        this->prev_read = 0;
    }
    this->provisioned_data.insert(this->provisioned_data.end(), data.begin(), data.end());
}

auto simple_stream::next_chunk() -> std::optional<std::span<uint8_t const>>
{
    if (this->prev_read > 0) {
        this->provisioned_data.erase(this->provisioned_data.begin(),
                                     this->provisioned_data.begin() + static_cast<diff_t>(this->prev_read));
    }

    auto avail      = this->provisioned_data.size();
    avail           = std::min(avail, static_cast<size_t>(std::numeric_limits<uint16_t>::max()));
    this->prev_read = avail - (avail % this->chunk_size);

    if (this->prev_read == 0) {
        return std::nullopt;
    }

    return std::span(this->provisioned_data).first(this->prev_read);
}

auto ksnp_simple_stream_create(ksnp_stream **stream_ptr, uint16_t chunk_size) noexcept -> ksnp_error
{
    try {
        auto *stream = new struct simple_stream(chunk_size);
        *stream_ptr  = stream;
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

void ksnp_simple_stream_destroy(ksnp_stream *stream) noexcept
{
    delete static_cast<simple_stream *>(stream);
}

auto ksnp_simple_stream_add_key_data(ksnp_stream *stream, ksnp_data key_data) noexcept -> ksnp_error
{
    try {
        static_cast<simple_stream *>(stream)->add_key_data(std::span(key_data.data, key_data.data + key_data.len));
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto simple_stream::stream_has_chunk(ksnp_stream const *stream) noexcept -> bool
{
    auto const *simple_stream = static_cast<::simple_stream const *>(stream);
    return (simple_stream->provisioned_data.size() - simple_stream->prev_read) >= simple_stream->chunk_size;
}

auto simple_stream::stream_next_chunk(ksnp_stream *stream, struct ksnp_data *data, uint16_t max_count) noexcept
    -> ksnp_error
{
    // Always returns exactly 1 chunk.
    (void)max_count;

    try {
        if (auto chunk = static_cast<simple_stream *>(stream)->next_chunk(); chunk.has_value()) {
            data->data = const_cast<unsigned char *>(chunk->data());
            data->len  = static_cast<uint32_t>(chunk->size());
        } else {
            data->data = nullptr;
            data->len  = 0;
        }
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_create(struct ksnp_server **server, ksnp_message_context *ctx) noexcept -> ksnp_error
try {
    *server = nullptr;
    *server = new ksnp_server(ctx);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

void ksnp_server_destroy(struct ksnp_server *server) noexcept
{
    delete server;
}

auto ksnp_server_want_read(struct ksnp_server const *server) noexcept -> bool
{
    return server->want_read();
}

auto ksnp_server_read_data(struct ksnp_server *server, uint8_t const *data, size_t *len) noexcept -> ksnp_error
{
    try {
        *len = server->read_data(std::span(data, data + *len));
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_next_event(struct ksnp_server *server, ksnp_server_event *event) noexcept -> ksnp_error
{
    try {
        if (auto evt = server->next_event(); evt.has_value()) {
            *event = into_event(*evt);
        } else {
            *event = ::ksnp_server_event{.type = ksnp_server_event_type::KSNP_SERVER_EVENT_NONE, .none = {}};
        }
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_want_write(struct ksnp_server const *server) noexcept -> bool
{
    return server->want_write();
}

auto ksnp_server_write_data(struct ksnp_server *server, uint8_t *data, size_t *len) noexcept -> ksnp_error
{
    try {
        *len = server->write_data(std::span(data, data + *len));
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_open_stream_ok(struct ksnp_server                       *server,
                                struct ksnp_stream                       *stream,
                                struct ksnp_stream_accepted_params const *params) noexcept -> ksnp_error
{
    try {
        server->open_stream_ok(stream, params);
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_open_stream_fail(struct ksnp_server                  *server,
                                  ksnp_status_code                     reason,
                                  struct ksnp_stream_qos_params const *params,
                                  char const                          *message) noexcept -> ksnp_error
{
    try {
        server->open_stream_fail(reason, params, message);
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_close_stream(struct ksnp_server *server, struct ksnp_stream **stream) noexcept -> ksnp_error
{
    try {
        *stream = server->close_stream();
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_suspend_stream_ok(struct ksnp_server *server, uint32_t timeout, struct ksnp_stream **stream) noexcept
    -> ksnp_error
{
    try {
        *stream = server->suspend_stream_ok(timeout);
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_suspend_stream_fail(struct ksnp_server *server, ksnp_status_code reason, char const *message) noexcept
    -> ksnp_error
{
    try {
        server->suspend_stream_fail(reason, message);
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_current_stream(struct ksnp_server const *server) noexcept -> ksnp_stream *
{
    return server->get_stream();
}

auto ksnp_server_keep_alive_ok(struct ksnp_server *server) noexcept -> ksnp_error
{
    try {
        server->keep_alive_ok();
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_keep_alive_fail(struct ksnp_server *server, ksnp_status_code reason, char const *message) noexcept
    -> ksnp_error
{
    try {
        server->keep_alive_fail(reason, message);
        return ksnp_error::KSNP_E_NO_ERROR;
    }
    CATCH_ALL
}

auto ksnp_server_close_connection(struct ksnp_server *server, ksnp_close_direction dir) noexcept -> ksnp_error
try {
    server->close_connection(dir);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL