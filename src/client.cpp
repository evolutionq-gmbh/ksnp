#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>

#include <json-c/json_types.h>

#include "client.hpp"
#include "helpers.hpp"
#include "ksnp/client.h"
#include "ksnp/messages.h"
#include "ksnp/serde.h"
#include "ksnp/types.h"

using namespace ksnp;

ksnp_client::ksnp_client(ksnp_message_context *connection)
    : connection(connection)
    , stream_state(stream_state::closed)
    , in_shutdown(false)
    , registered_capacity(0)
    , chunk_size(0)
{
    this->push_message(::ksnp_msg_version{.minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                                          .maximum_version = ksnp_protocol_version::PROTOCOL_V1});
}

auto ksnp_client::want_read() const noexcept -> bool
{
    if (this->stream_state == stream_state::error) {
        return false;
    }
    return ::ksnp_message_context_want_read(this->connection);
}

auto ksnp_client::read_data(std::span<uint8_t const> data) -> size_t
{

    size_t len = data.size();
    if (auto res = ::ksnp_message_context_read_data(this->connection, data.data(), &len);
        res != ksnp_error::KSNP_E_NO_ERROR) {
        throw ksnp::exception(res);
    }
    return len;
}

auto ksnp_client::want_write() const noexcept -> bool
{
    return ::ksnp_message_context_want_write(this->connection);
}

void ksnp_client::flush_data()
{
    // Nothing to do
}

auto ksnp_client::write_data(std::span<uint8_t> data) -> size_t
{
    this->flush_data();

    auto len = data.size();
    if (auto res = ::ksnp_message_context_write_data(this->connection, data.data(), &len);
        res != ksnp_error::KSNP_E_NO_ERROR) {
        throw ksnp::exception(res);
    }
    return len;
}

auto ksnp_client::next_event() -> std::optional<client_event>
{
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
            return ksnp_client_event_error{
                .code        = protocol_error.code,
                .description = protocol_error.description,
            };
        } else {
            throw ksnp::exception(res);
        }
    }
}

auto ksnp_client::process_message(ksnp_message const &msg)  // NOLINT(readability-function-cognitive-complexity)
    -> std::optional<client_event>
{
    if (this->stream_state == stream_state::error) {
        return std::nullopt;
    }

    if (!this->version) {
        overloads version_msg_visitor{[this](::ksnp_msg_error msg) -> std::optional<client_event> {
                                          this->stream_state = stream_state::error;
                                          return ksnp_client_event_error{
                                              .code        = msg.code,
                                              .description = nullptr,
                                          };
                                      },
                                      [this](::ksnp_msg_version msg) -> std::optional<client_event> {
                                          if (msg.minimum_version != ksnp_protocol_version::PROTOCOL_V1
                                              || msg.maximum_version < ksnp_protocol_version::PROTOCOL_V1) {
                                              throw version_exception();
                                          }
                                          this->version = ksnp_protocol_version::PROTOCOL_V1;
                                          return ::ksnp_client_event_handshake{
                                              .protocol = *this->version,
                                          };
                                      },
                                      [this](auto) -> std::optional<client_event> {
                                          return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                                      }};
        return std::visit(version_msg_visitor, into_message(msg));
    }

    overloads msg_visitor{[this](::ksnp_msg_error msg) -> std::optional<client_event> {
                              this->stream_state = stream_state::error;
                              return ksnp_client_event_error{
                                  .code        = msg.code,
                                  .description = nullptr,
                              };
                          },
                          [this](ksnp_msg_open_stream_reply msg) -> std::optional<client_event> {
                              if (this->stream_state != stream_state::opening) {
                                  return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              }
                              if (msg.code == ksnp_status_code::KSNP_STATUS_SUCCESS) {
                                  this->stream_state = stream_state::open;
                              } else {
                                  this->chunk_size          = 0;
                                  this->registered_capacity = 0;
                              }
                              return ::ksnp_client_event_stream_open{
                                  .code       = msg.code,
                                  .parameters = {.reply = msg.parameters.reply},
                                  .message    = msg.message,
                              };
                          },
                          [this](::ksnp_msg_close_stream_reply) -> std::optional<client_event> {
                              switch (this->stream_state) {
                              case stream_state::closed:
                              case stream_state::opening:
                              case stream_state::suspending:
                              case stream_state::open:
                                  return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::closing:
                                  this->stream_state = stream_state::closed;
                                  return ::ksnp_client_event_stream_close{
                                      .code    = ksnp_status_code::KSNP_STATUS_SUCCESS,
                                      .message = nullptr,
                                  };
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [this](::ksnp_msg_close_stream_notify msg) -> std::optional<client_event> {
                              switch (this->stream_state) {
                              case stream_state::closed:
                              case stream_state::opening:
                                  return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::open:
                              case stream_state::suspending:
                              case stream_state::closing:
                                  this->stream_state = stream_state::closed;
                                  return ::ksnp_client_event_stream_close{
                                      .code    = msg.code,
                                      .message = msg.message,
                                  };
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [this](::ksnp_msg_suspend_stream_reply msg) -> std::optional<client_event> {
                              switch (this->stream_state) {
                              case stream_state::closed:
                              case stream_state::opening:
                              case stream_state::open:
                              case stream_state::closing:
                                  return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::suspending:
                                  this->stream_state = stream_state::closed;
                                  return ::ksnp_client_event_stream_suspend{
                                      .code    = msg.code,
                                      .timeout = msg.code == ksnp_status_code::KSNP_STATUS_SUCCESS ? msg.timeout : 0,
                                      .message = msg.message,
                                  };
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [this](::ksnp_msg_suspend_stream_notify msg) -> std::optional<client_event> {
                              switch (this->stream_state) {
                              case stream_state::closed:
                              case stream_state::opening:
                                  return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::closing:
                                  return std::nullopt;
                              case stream_state::open:
                                  this->push_message(ksnp_msg_suspend_stream{.timeout = msg.timeout});
                                  // fallthrough
                              case stream_state::suspending:
                                  this->stream_state = stream_state::closed;
                                  return ::ksnp_client_event_stream_suspend{
                                      .code    = msg.code,
                                      .timeout = msg.timeout,
                                      .message = nullptr,
                                  };
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [this](::ksnp_msg_key_data_notify msg) -> std::optional<client_event> {
                              switch (this->stream_state) {
                              case stream_state::open:
                                  if (msg.key_data.len % this->chunk_size != 0
                                      || this->registered_capacity < msg.key_data.len) {
                                      return on_error(ksnp_error_code::KSNP_PROT_E_INVALID_CHUNK);
                                  }
                                  this->registered_capacity -= msg.key_data.len;
                                  return ::ksnp_client_event_key_data{
                                      .key_data   = msg.key_data,
                                      .parameters = msg.parameters,
                                  };

                              case stream_state::suspending:
                              case stream_state::closing:
                                  return std::nullopt;
                              case stream_state::closed:
                              case stream_state::opening:
                                  return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                              case stream_state::error:
                              default:
                                  throw std::logic_error("invalid stream state");
                              }
                          },
                          [](::ksnp_msg_keep_alive_stream_reply msg) -> std::optional<client_event> {
                              return ::ksnp_client_event_keep_alive{
                                  .code    = msg.code,
                                  .message = msg.message,
                              };
                          },
                          [this](auto) -> std::optional<client_event> {
                              return on_error(ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE);
                          }};

    return std::visit(msg_visitor, into_message(msg));
}

void ksnp_client::push_message(message_t const msg)
{
    if (this->in_shutdown) {
        return;
    }
    auto c_msg = into_message(msg);
    if (auto res = ::ksnp_message_context_write_message(this->connection, &c_msg); res != ksnp_error::KSNP_E_NO_ERROR) {
        throw ksnp::exception(res);
    }
}

auto ksnp_client::on_error(ksnp_error_code err) -> client_event
{
    if (this->stream_state != stream_state::error) {
        this->push_message(ksnp_msg_error{.code = err});
    }
    this->stream_state = stream_state::error;
    return ksnp_client_event_error{.code = err, .description = nullptr};
}

void ksnp_client::open_stream(ksnp_stream_open_params const *parameters)
{
    if (this->stream_state != stream_state::closed) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    this->stream_state        = stream_state::opening;
    this->chunk_size          = parameters->chunk_size != 0 ? parameters->chunk_size : 1;
    this->registered_capacity = parameters->capacity;
    this->push_message(::ksnp_msg_open_stream{.parameters = parameters});
}

void ksnp_client::close_stream()
{
    if (this->stream_state != stream_state::open) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    this->stream_state = stream_state::closing;
    this->push_message(::ksnp_msg_close_stream{});
}

void ksnp_client::suspend_stream(uint32_t timeout)
{
    if (this->stream_state != stream_state::open) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    this->stream_state = stream_state::suspending;
    this->push_message(::ksnp_msg_suspend_stream{.timeout = timeout});
}

void ksnp_client::add_capacity(uint32_t additional_capacity)
{
    if (this->stream_state != stream_state::open) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    if ((std::numeric_limits<uint32_t>::max() - this->registered_capacity) < additional_capacity) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }
    this->registered_capacity += additional_capacity;
    this->push_message(::ksnp_msg_capacity_notify{.additional_capacity = additional_capacity});
}

void ksnp_client::keep_alive(uuid_t const &stream_id)
{
    auto msg = ::ksnp_msg_keep_alive_stream{};
    std::ranges::copy(stream_id, std::begin(msg.key_stream_id));
    this->push_message(msg);
}

void ksnp_client::close_connection(ksnp_close_direction dir)
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
        this->in_shutdown = true;
    }
}

auto ksnp_client_create(struct ksnp_client **client, ksnp_message_context *ctx) noexcept -> ksnp_error
try {
    *client = nullptr;
    *client = new ksnp_client(ctx);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

void ksnp_client_destroy(struct ksnp_client *client) noexcept
{
    delete client;
}

auto ksnp_client_want_read(struct ksnp_client const *client) noexcept -> bool
{
    return client->want_read();
}

auto ksnp_client_read_data(struct ksnp_client *client, uint8_t const *data, size_t *len) noexcept -> ksnp_error
try {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    auto buffer = std::span{data, *len};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    *len = client->read_data(buffer);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_next_event(struct ksnp_client *client, ksnp_client_event *event_ptr) noexcept -> ksnp_error
try {
    auto event = client->next_event();
    if (event.has_value()) {
        *event_ptr = into_event(*event);
    } else {
        *event_ptr = ksnp_client_event{.type = ksnp_client_event_type::KSNP_CLIENT_EVENT_NONE, .none = {}};
    }
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_want_write(struct ksnp_client const *client) noexcept -> bool
{
    return client->want_write();
}

auto ksnp_client_flush_data(struct ksnp_client *client) noexcept -> ksnp_error
try {
    client->flush_data();
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_write_data(struct ksnp_client *client, uint8_t *data, size_t *len) noexcept -> ksnp_error
try {
#ifdef __clang__
#pragma clang unsafe_buffer_usage begin
#endif
    auto buffer = std::span{data, *len};
#ifdef __clang__
#pragma clang unsafe_buffer_usage end
#endif
    *len = client->write_data(buffer);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_open_stream(struct ksnp_client *client, ksnp_stream_open_params const *parameters) noexcept
    -> ksnp_error
try {
    client->open_stream(parameters);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_close_stream(struct ksnp_client *client) noexcept -> ksnp_error
try {
    client->close_stream();
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_suspend_stream(struct ksnp_client *client, uint32_t timeout) noexcept -> ksnp_error
try {
    client->suspend_stream(timeout);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_add_capacity(struct ksnp_client *client, uint32_t additional_capacity) noexcept -> ksnp_error
try {
    client->add_capacity(additional_capacity);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_keep_alive(struct ksnp_client *client, ksnp_key_stream_id const *stream_id) noexcept -> ksnp_error
try {
    client->keep_alive(*stream_id);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL

auto ksnp_client_close_connection(struct ksnp_client *client, ksnp_close_direction dir) noexcept -> ksnp_error
try {
    client->close_connection(dir);
    return ksnp_error::KSNP_E_NO_ERROR;
}
CATCH_ALL