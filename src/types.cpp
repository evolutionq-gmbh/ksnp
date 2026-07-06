#include "ksnp/types.h"

auto ksnp_status_code_description(ksnp_status_code code) -> char const *
{
    switch (code) {  // NOLINT(hicpp-multiway-paths-covered)
    case ksnp_status_code::KSNP_STATUS_SUCCESS:
        return "operation completed successfully";
    case ksnp_status_code::KSNP_STATUS_INVALID_PARAMETER:
        return "parameter value out of range";
    case ksnp_status_code::KSNP_STATUS_OPERATION_NOT_SUPPORTED:
        return "operation not supported";
    case ksnp_status_code::KSNP_STATUS_NOTIFY_DUE_TO_PEER:
        return "stream state changed by peer";
    case ksnp_status_code::KSNP_STATUS_INSUFFICIENT_RESOURCES:
        return "insufficient resources";
    case ksnp_status_code::KSNP_STATUS_UNSUPPORTED_EXTENSION:
        return "required extension is not supported";
    case ksnp_status_code::KSNP_STATUS_MALFORMED_EXTENSION:
        return "extension is malformed";
    case ksnp_status_code::KSNP_STATUS_TIMEOUT:
        return "timeout occurred";
    case ksnp_status_code::KSNP_STATUS_STREAM_IN_USE:
        return "key stream is in use";
    case ksnp_status_code::KSNP_STATUS_UNAUTHENTICATED:
        return "client unauthenticated";
    case ksnp_status_code::KSNP_STATUS_UNAUTHORIZED:
        return "client unauthorized";
    case ksnp_status_code::KSNP_STATUS_QOS_OUT_OF_RANGE:
        return "QoS value(s) out of supported range";
    case ksnp_status_code::KSNP_STATUS_QOS_UNSATISFIABLE:
        return "QoS value(s) cannot be satisfied";
    case ksnp_status_code::KSNP_STATUS_DESTINATION_UNKNOWN:
        return "stream destination not known";
    case ksnp_status_code::KSNP_STATUS_DESTINATION_UNAVAILABLE:
        return "stream destination not reachable";
    case ksnp_status_code::KSNP_STATUS_STREAM_CLOSED:
        return "stream is closed";
    default:
        return nullptr;
    }
}

auto ksnp_protocol_error_description(ksnp_error_code code) -> char const *
{
    switch (code) {
    case ksnp_error_code::KSNP_PROT_E_UNKNOWN_ERROR:
        return "unknown error";
    case ksnp_error_code::KSNP_PROT_E_UNEXPECTED_MESSAGE:
        return "message unexpected";
    case ksnp_error_code::KSNP_PROT_E_EXCESSIVE_CAPACITY:
        return "capacity out of bounds";
    case ksnp_error_code::KSNP_PROT_E_INVALID_CHUNK:
        return "chunk size invalid";
    case ksnp_error_code::KSNP_PROT_E_TIMEOUT:
        return "operation timed out";
    case ksnp_error_code::KSNP_PROT_E_BAD_MSG_TYPE:
        return "invalid message type";
    case ksnp_error_code::KSNP_PROT_E_BAD_MSG_LENGTH:
        return "message length out of bounds";
    case ksnp_error_code::KSNP_PROT_E_BAD_JSON:
        return "malformed JSON";
    case ksnp_error_code::KSNP_PROT_E_BAD_JSON_TYPE:
        return "JSON value does not match schema";
    case ksnp_error_code::KSNP_PROT_E_BAD_JSON_LENGTH:
        return "invalid size of JSON payload";
    case ksnp_error_code::KSNP_PROT_E_JSON_KEY_MISSING:
        return "missing JSON key";
    case ksnp_error_code::KSNP_PROT_E_BAD_JSON_KEY:
        return "unexpected JSON key";
    case ksnp_error_code::KSNP_PROT_E_BAD_JSON_VAL:
        return "JSON value out of bounds";
    case ksnp_error_code::KSNP_PROT_E_JSON_MISSING:
        return "JSON data is missing";
    case ksnp_error_code::KSNP_PROT_E_INCOMPLETE_MSG:
        return "incomplete message, but receiving channel closed";
    default:
        return nullptr;
    }
}

auto ksnp_error_description(ksnp_error error) -> char const *
{
    switch (error) {
    case ksnp_error::KSNP_E_NO_ERROR:
        return "operation successful";
    case ksnp_error::KSNP_E_UNKNOWN:
        return "unknown error";
    case ksnp_error::KSNP_E_NO_MEM:
        return "out of memory";
    case ksnp_error::KSNP_E_PROTOCOL_ERROR:
        return "protocol error";
    case ksnp_error::KSNP_E_SER_MSG_TOO_LARGE:
        return "message too large";
    case ksnp_error::KSNP_E_SER_JSON_TOO_LARGE:
        return "JSON payload too large";
    case ksnp_error::KSNP_E_UNSUPPORTED_VERSION:
        return "protocol version not supported";
    case ksnp_error::KSNP_E_INVALID_OPERATION:
        return "operation cannot be performed at this time";
    case ksnp_error::KSNP_E_INVALID_ARGUMENT:
        return "invalid argument";
    case ksnp_error::KSNP_E_KEY_DATA_TOO_LARGE:
        return "too much key data";
    case ksnp_error::KSNP_E_KEY_DATA_NOT_CHUNKED:
        return "key data is not chunked";
    case ksnp_error::KSNP_E_INVALID_MESSAGE_TYPE:
        return "message type invalid";
    case ksnp_error::KSNP_E_INVALID_EVENT_TYPE:
        return "event type invalid";
    case ksnp_error::KSNP_E_CHUNK_SIZE_TOO_LARGE:
        return "chunk size too large";
    case ksnp_error::KSNP_E_INSUFFICIENT_BUFFER:
        return "buffer too small";
    default:
        return "unknown error";
    }
}
