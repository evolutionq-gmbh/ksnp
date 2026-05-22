#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>

#include <json-c/json_types.h>

#include "helpers.hpp"
#include "ksnp/client.h"
#include "ksnp/client.hpp"
#include "ksnp/messages.h"
#include "ksnp/serde.h"
#include "ksnp/types.h"
#include "ksnp/types.hpp"

namespace ksnp
{

auto client_event::into_event() const noexcept -> ksnp_client_event
{
    auto const visitor = overloads{
        [](ksnp_client_event_handshake evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type      = ksnp_client_event_type::KSNP_CLIENT_EVENT_HANDSHAKE,
                .handshake = evt,
            };
        },
        [](ksnp_client_event_stream_open evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type        = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_OPEN,
                .stream_open = evt,
            };
        },
        [](ksnp_client_event_stream_close evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type         = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_CLOSE,
                .stream_close = evt,
            };
        },
        [](ksnp_client_event_stream_suspend evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type           = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_SUSPEND,
                .stream_suspend = evt,
            };
        },
        [](ksnp_client_event_key_data evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type     = ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_KEY_DATA,
                .key_data = evt,
            };
        },
        [](ksnp_client_event_keep_alive evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type       = ksnp_client_event_type::KSNP_CLIENT_EVENT_KEEP_ALIVE,
                .keep_alive = evt,
            };
        },
        [](ksnp_client_event_error evt) -> ksnp_client_event {
            return ksnp_client_event{
                .type  = ksnp_client_event_type::KSNP_CLIENT_EVENT_ERROR,
                .error = evt,
            };
        },
    };
    return std::visit(visitor, *this);
}

auto client_event::from_event(ksnp_client_event event) -> std::optional<client_event>
{
    switch (event.type) {
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_NONE:
        return std::nullopt;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_HANDSHAKE:
        return event.handshake;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_OPEN:
        return event.stream_open;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_CLOSE:
        return event.stream_close;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_SUSPEND:
        return event.stream_suspend;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_KEY_DATA:
        return event.key_data;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_KEEP_ALIVE:
        return event.keep_alive;
    case ksnp_client_event_type::KSNP_CLIENT_EVENT_ERROR:
        return event.error;
    default:
        throw exception(ksnp_error::KSNP_E_INVALID_EVENT_TYPE);
    }
}

client::client(ksnp::message_context &connection)
    : connection(&connection)
    , stream_state(stream_state::closed)
    , in_shutdown(false)
    , give_eof(false)
    , registered_capacity(0)
    , chunk_size(0)
{
    this->push_message(::ksnp_msg_version{.minimum_version = ksnp_protocol_version::PROTOCOL_V1,
                                          .maximum_version = ksnp_protocol_version::PROTOCOL_V1});
}

auto client::want_read() const noexcept -> bool
{
    if (this->stream_state == stream_state::error) {
        return false;
    }
    return this->connection->want_read();
}

auto client::read_data(std::span<uint8_t const> data) -> size_t
{
    if (data.empty()) {
        this->close_connection(ksnp_close_direction::KSNP_CLOSE_READ);
        return 0;
    }

    return this->connection->read_data(data);
}

auto client::want_write() const noexcept -> bool
{
    return this->connection->want_write() || this->give_eof;
}

void client::flush_data()
{
    if (!this->connection->want_write() && this->give_eof) {
        // If no data needs to be written by the context and give_eof is true,
        // want_write returned true. A "flush" will clear the EOF flag so it
        // does not get indicated twice.
        this->give_eof = false;
    }
}

auto client::write_data(std::span<uint8_t> data) -> size_t
{
    this->flush_data();
    return this->connection->write_data(data);
}

auto client::next_event() -> std::optional<client_event>
{
    if (this->stream_state == stream_state::error) {
        return std::nullopt;
    }

    while (true) {
        std::optional<message> message;
        try {
            message = this->connection->next_message();
        } catch (protocol_exception &e) {
            return ksnp_client_event_error{
                .code        = e.code(),
                .description = e.description(),
            };
        }

        if (!message.has_value()) {
            return std::nullopt;
        }
        if (auto event = this->process_message(*message); event.has_value()) {
            return event;
        }
    }
}

auto client::process_message(message const &msg)  // NOLINT(readability-function-cognitive-complexity)
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
        return std::visit(version_msg_visitor, msg);
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
                                  [[fallthrough]];
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

    return std::visit(msg_visitor, msg);
}

void client::push_message(message const msg)
{
    if (this->in_shutdown) {
        return;
    }
    this->connection->write_message(msg);
}

auto client::on_error(ksnp_error_code err) -> client_event
{
    if (this->stream_state != stream_state::error) {
        this->push_message(ksnp_msg_error{.code = err});
    }
    this->stream_state = stream_state::error;
    return ksnp_client_event_error{.code = err, .description = nullptr};
}

void client::open_stream(ksnp_stream_open_params const *parameters)
{
    if (this->stream_state != stream_state::closed) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    this->stream_state        = stream_state::opening;
    this->chunk_size          = parameters->chunk_size != 0 ? parameters->chunk_size : 1;
    this->registered_capacity = parameters->capacity;
    this->push_message(::ksnp_msg_open_stream{.parameters = parameters});
}

void client::close_stream()
{
    if (this->stream_state != stream_state::open) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    this->stream_state = stream_state::closing;
    this->push_message(::ksnp_msg_close_stream{});
}

void client::suspend_stream(uint32_t timeout)
{
    if (this->stream_state != stream_state::open) {
        throw ksnp::exception(ksnp_error::KSNP_E_INVALID_OPERATION);
    }
    this->stream_state = stream_state::suspending;
    this->push_message(::ksnp_msg_suspend_stream{.timeout = timeout});
}

void client::add_capacity(uint32_t additional_capacity)
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

void client::keep_alive(uuid_t const &stream_id)
{
    auto msg = ::ksnp_msg_keep_alive_stream{};
    std::ranges::copy(stream_id, std::begin(msg.key_stream_id));
    this->push_message(msg);
}

void client::close_connection(ksnp_close_direction dir)
{
    bool close_read  = dir == ksnp_close_direction::KSNP_CLOSE_READ || dir == ksnp_close_direction::KSNP_CLOSE_BOTH;
    bool close_write = dir == ksnp_close_direction::KSNP_CLOSE_WRITE || dir == ksnp_close_direction::KSNP_CLOSE_BOTH;
    if (!close_read && !close_write) {
        throw exception(ksnp_error::KSNP_E_INVALID_ARGUMENT);
    }

    if (close_read) {
        this->connection->read_data({});
    }

    if (close_write) {
        if (this->in_shutdown) {
            throw exception(ksnp_error::KSNP_E_INVALID_OPERATION);
        }
        this->in_shutdown = true;
        this->give_eof    = true;
    }
}

}  // namespace ksnp

// Wrapper for the C++ class into a C struct. Note that this is not POD, but the
// type is opaque to the API.
struct ksnp_client : ksnp::client {
    using ksnp::client::client;
};

auto ksnp_client_create(struct ksnp_client **client, ksnp_message_context *ctx) noexcept -> ksnp_error
try {
    *client = nullptr;
    *client = new ksnp_client(*reinterpret_cast<ksnp::message_context *>(ctx));
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
        *event_ptr = event->into_event();
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
