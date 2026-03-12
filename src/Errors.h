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

#ifndef ERRORS_H
#define ERRORS_H

#include <cstdint>

/* ── Protocol Error Codes (match server ProtocolError enum) ─────────── */

enum class Error : uint16_t {
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
    TIME_SYNC_FAILED            = 3006,
    BOOTSTRAP_FAILED            = 3007,

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

inline const char* error_str(Error e) {
    switch (e) {
        case Error::OK:                         return "OK";
        case Error::VERSION_MISMATCH:           return "VERSION_MISMATCH";
        case Error::TIMESTAMP_EXPIRED:          return "TIMESTAMP_EXPIRED";
        case Error::NONCE_REUSED:               return "NONCE_REUSED";
        case Error::HASH_MISMATCH:              return "HASH_MISMATCH";
        case Error::SIGNATURE_INVALID:          return "SIGNATURE_INVALID";
        case Error::SEQUENCE_VIOLATION:          return "SEQUENCE_VIOLATION";
        case Error::PAYLOAD_TOO_LARGE:          return "PAYLOAD_TOO_LARGE";
        case Error::DEVICE_NOT_FOUND:           return "DEVICE_NOT_FOUND";
        case Error::DEVICE_OFFLINE:             return "DEVICE_OFFLINE";
        case Error::DEVICE_QUARANTINED:         return "DEVICE_QUARANTINED";
        case Error::UNKNOWN_ACTION:             return "UNKNOWN_ACTION";
        case Error::PERMISSION_DENIED:          return "PERMISSION_DENIED";
        case Error::INVALID_PARAMS:             return "INVALID_PARAMS";
        case Error::CAPABILITY_NOT_REGISTERED:  return "CAPABILITY_NOT_REGISTERED";
        case Error::BROKER_CONNECT_FAILED:      return "Broker connect failed";
        case Error::BROKER_PUBLISH_FAILED:      return "MQTT_PUBLISH_FAILED";
        case Error::BROKER_SUBSCRIBE_FAILED:    return "MQTT_SUBSCRIBE_FAILED";
        case Error::TLS_HANDSHAKE_FAILED:       return "TLS_HANDSHAKE_FAILED";
        case Error::WIFI_CONNECT_FAILED:        return "WiFi connect failed";
        case Error::TIME_SYNC_FAILED:           return "Time sync failed";
        case Error::BOOTSTRAP_FAILED:           return "Bootstrap failed";
        case Error::CRYPTO_INIT_FAILED:         return "CRYPTO_INIT_FAILED";
        case Error::HMAC_COMPUTE_FAILED:        return "HMAC_COMPUTE_FAILED";
        case Error::SHA256_COMPUTE_FAILED:      return "SHA256_COMPUTE_FAILED";
        case Error::AES_DECRYPT_FAILED:         return "AES_DECRYPT_FAILED";
        case Error::RNG_FAILED:                 return "RNG_FAILED";
        case Error::SECRET_NOT_FOUND:           return "SECRET_NOT_FOUND";
        case Error::SECRET_CORRUPT:             return "SECRET_CORRUPT";
        case Error::FRAME_TOO_SHORT:            return "FRAME_TOO_SHORT";
        case Error::FRAME_MAGIC_INVALID:        return "FRAME_MAGIC_INVALID";
        case Error::FRAME_VERSION_INVALID:      return "FRAME_VERSION_INVALID";
        case Error::FRAME_TYPE_INVALID:         return "FRAME_TYPE_INVALID";
        case Error::FRAME_LENGTH_INVALID:       return "FRAME_LENGTH_INVALID";
        case Error::FRAME_UTF8_INVALID:         return "FRAME_UTF8_INVALID";
        case Error::FRAME_JSON_INVALID:         return "FRAME_JSON_INVALID";
        case Error::FRAME_SCHEMA_INVALID:       return "FRAME_SCHEMA_INVALID";
        case Error::STORAGE_INIT_FAILED:        return "STORAGE_INIT_FAILED";
        case Error::STORAGE_READ_FAILED:        return "STORAGE_READ_FAILED";
        case Error::STORAGE_WRITE_FAILED:       return "STORAGE_WRITE_FAILED";
        case Error::INTERNAL_ERROR:             return "INTERNAL_ERROR";
        case Error::NOT_INITIALIZED:            return "NOT_INITIALIZED";
        case Error::PROTOCOL_NOT_READY:         return "PROTOCOL_NOT_READY";
        case Error::BUFFER_OVERFLOW:            return "BUFFER_OVERFLOW";
        default:                                     return "UNKNOWN_ERROR";
    }
}

#endif /* ERRORS_H */
