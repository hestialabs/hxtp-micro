/*
 * HXTP Embedded SDK v1.0
 * Error Code Definitions
 *
 * Maps to server-side ProtocolError enum values.
 * Platform-agnostic. NO Arduino includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_ERRORS_H
#define HXTP_ERRORS_H

#include <cstdint>

/* ── Protocol Error Codes (match server ProtocolError enum) ─────────── */

enum class HxtpError : uint16_t {
    /* Success */
    OK                          = 0,

    /* Protocol-level errors */
    VERSION_MISMATCH            = 1001,
    TIMESTAMP_EXPIRED           = 1002,
    NONCE_REUSED                = 1003,
    HASH_MISMATCH               = 1004,
    SIGNATURE_INVALID           = 1005,
    SEQUENCE_VIOLATION          = 1006,
    PAYLOAD_TOO_LARGE           = 1007,

    /* Device / capability errors */
    DEVICE_NOT_FOUND            = 2001,
    DEVICE_OFFLINE              = 2002,
    DEVICE_QUARANTINED          = 2003,
    UNKNOWN_ACTION              = 2004,
    PERMISSION_DENIED           = 2005,
    INVALID_PARAMS              = 2006,
    CAPABILITY_NOT_REGISTERED   = 2007,

    /* Transport errors (prefixed to avoid PubSubClient macro clashes) */
    BROKER_CONNECT_FAILED       = 3001,
    BROKER_PUBLISH_FAILED       = 3002,
    BROKER_SUBSCRIBE_FAILED     = 3003,
    TLS_HANDSHAKE_FAILED        = 3004,
    WIFI_CONNECT_FAILED         = 3005,

    /* Crypto errors */
    CRYPTO_INIT_FAILED          = 4001,
    HMAC_COMPUTE_FAILED         = 4002,
    SHA256_COMPUTE_FAILED       = 4003,
    AES_DECRYPT_FAILED          = 4004,
    RNG_FAILED                  = 4005,
    SECRET_NOT_FOUND            = 4006,
    SECRET_CORRUPT              = 4007,

    /* Frame errors */
    FRAME_TOO_SHORT             = 5001,
    FRAME_MAGIC_INVALID         = 5002,
    FRAME_VERSION_INVALID       = 5003,
    FRAME_TYPE_INVALID          = 5004,
    FRAME_LENGTH_INVALID        = 5005,
    FRAME_UTF8_INVALID          = 5006,
    FRAME_JSON_INVALID          = 5007,
    FRAME_SCHEMA_INVALID        = 5008,

    /* Storage errors */
    STORAGE_INIT_FAILED         = 6001,
    STORAGE_READ_FAILED         = 6002,
    STORAGE_WRITE_FAILED        = 6003,

    /* Internal */
    INTERNAL_ERROR              = 9001,
    NOT_INITIALIZED             = 9002,
    PROTOCOL_NOT_READY          = 9003,
    BUFFER_OVERFLOW             = 9004,
};

/* ── Error code to string (for logging / debug) ─────────────────────── */

inline const char* hxtp_error_str(HxtpError e) {
    switch (e) {
        case HxtpError::OK:                         return "OK";
        case HxtpError::VERSION_MISMATCH:           return "VERSION_MISMATCH";
        case HxtpError::TIMESTAMP_EXPIRED:          return "TIMESTAMP_EXPIRED";
        case HxtpError::NONCE_REUSED:               return "NONCE_REUSED";
        case HxtpError::HASH_MISMATCH:              return "HASH_MISMATCH";
        case HxtpError::SIGNATURE_INVALID:          return "SIGNATURE_INVALID";
        case HxtpError::SEQUENCE_VIOLATION:          return "SEQUENCE_VIOLATION";
        case HxtpError::PAYLOAD_TOO_LARGE:          return "PAYLOAD_TOO_LARGE";
        case HxtpError::DEVICE_NOT_FOUND:           return "DEVICE_NOT_FOUND";
        case HxtpError::DEVICE_OFFLINE:             return "DEVICE_OFFLINE";
        case HxtpError::DEVICE_QUARANTINED:         return "DEVICE_QUARANTINED";
        case HxtpError::UNKNOWN_ACTION:             return "UNKNOWN_ACTION";
        case HxtpError::PERMISSION_DENIED:          return "PERMISSION_DENIED";
        case HxtpError::INVALID_PARAMS:             return "INVALID_PARAMS";
        case HxtpError::CAPABILITY_NOT_REGISTERED:  return "CAPABILITY_NOT_REGISTERED";
        case HxtpError::BROKER_CONNECT_FAILED:      return "MQTT_CONNECT_FAILED";
        case HxtpError::BROKER_PUBLISH_FAILED:      return "MQTT_PUBLISH_FAILED";
        case HxtpError::BROKER_SUBSCRIBE_FAILED:    return "MQTT_SUBSCRIBE_FAILED";
        case HxtpError::TLS_HANDSHAKE_FAILED:       return "TLS_HANDSHAKE_FAILED";
        case HxtpError::WIFI_CONNECT_FAILED:        return "WIFI_CONNECT_FAILED";
        case HxtpError::CRYPTO_INIT_FAILED:         return "CRYPTO_INIT_FAILED";
        case HxtpError::HMAC_COMPUTE_FAILED:        return "HMAC_COMPUTE_FAILED";
        case HxtpError::SHA256_COMPUTE_FAILED:      return "SHA256_COMPUTE_FAILED";
        case HxtpError::AES_DECRYPT_FAILED:         return "AES_DECRYPT_FAILED";
        case HxtpError::RNG_FAILED:                 return "RNG_FAILED";
        case HxtpError::SECRET_NOT_FOUND:           return "SECRET_NOT_FOUND";
        case HxtpError::SECRET_CORRUPT:             return "SECRET_CORRUPT";
        case HxtpError::FRAME_TOO_SHORT:            return "FRAME_TOO_SHORT";
        case HxtpError::FRAME_MAGIC_INVALID:        return "FRAME_MAGIC_INVALID";
        case HxtpError::FRAME_VERSION_INVALID:      return "FRAME_VERSION_INVALID";
        case HxtpError::FRAME_TYPE_INVALID:         return "FRAME_TYPE_INVALID";
        case HxtpError::FRAME_LENGTH_INVALID:       return "FRAME_LENGTH_INVALID";
        case HxtpError::FRAME_UTF8_INVALID:         return "FRAME_UTF8_INVALID";
        case HxtpError::FRAME_JSON_INVALID:         return "FRAME_JSON_INVALID";
        case HxtpError::FRAME_SCHEMA_INVALID:       return "FRAME_SCHEMA_INVALID";
        case HxtpError::STORAGE_INIT_FAILED:        return "STORAGE_INIT_FAILED";
        case HxtpError::STORAGE_READ_FAILED:        return "STORAGE_READ_FAILED";
        case HxtpError::STORAGE_WRITE_FAILED:       return "STORAGE_WRITE_FAILED";
        case HxtpError::INTERNAL_ERROR:             return "INTERNAL_ERROR";
        case HxtpError::NOT_INITIALIZED:            return "NOT_INITIALIZED";
        case HxtpError::PROTOCOL_NOT_READY:         return "PROTOCOL_NOT_READY";
        case HxtpError::BUFFER_OVERFLOW:            return "BUFFER_OVERFLOW";
        default:                                     return "UNKNOWN_ERROR";
    }
}

#endif /* HXTP_ERRORS_H */
