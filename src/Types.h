/*
 * HXTP Embedded SDK v1.0.3
 * Core Type Definitions
 *
 * Platform-agnostic types for the HXTP protocol.
 * NO Arduino, NO WiFi, NO MQTT includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef TYPES_H
#define TYPES_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include "Config.h"

/* ── Protocol Constants (FROZEN — do not modify) ────────────────────── */

static constexpr uint8_t  Magic[2]           = { 0x48, 0x58 };   /* "HX" */
static constexpr uint8_t  FramerVersion      = 3;
static constexpr uint8_t  ProtocolMajor      = 0;
static constexpr uint8_t  ProtocolMinor      = 1;

static constexpr char     VersionString[]    = "HxTP/3.0";
static constexpr char     CanonicalSep       = '|';

static constexpr uint8_t  HeaderSize         = 8;

/* ── Validation Limits ──────────────────────────────────────────────── */

static constexpr uint32_t MaxMessageAgeSec  = 300;   /* 5 minutes */
static constexpr uint32_t TimestampSkewSec  = 60;    /* 1 minute future */
static constexpr uint32_t NonceTtlSec       = 600;   /* 10 minutes */
static constexpr uint32_t MaxPayloadBytes   = 16384; /* 16 KB hard limit */

/* Frame buffer: overridable from Config.h */
#ifdef FrameBufOverride
static constexpr uint32_t FrameBufDefault   = FrameBufOverride;
#else
static constexpr uint32_t FrameBufDefault   = 4096;  /* 4 KB default buf */
#endif

/* ── Crypto Constants ───────────────────────────────────────────────── */

static constexpr size_t   Sha256Len          = 32;
static constexpr size_t   Sha256HexLen      = 64;
static constexpr size_t   HmacLen            = 32;
static constexpr size_t   HmacHexLen        = 64;
static constexpr size_t   SecretLen           = 32;
static constexpr size_t   SecretHexLen       = 64;
static constexpr size_t   NonceRawMin        = 16;
static constexpr size_t   NonceB64Min        = 22;
static constexpr size_t   AesGcmIvLen       = 12;
static constexpr size_t   AesGcmTagLen      = 16;
static constexpr size_t   AesKeyLen           = 32;

/* ── Nonce Ring Buffer Size ─────────────────────────────────────────── */

#ifdef NonceCacheSizeOverride
static constexpr size_t   NonceCacheSize     = NonceCacheSizeOverride;
#else
static constexpr size_t   NonceCacheSize     = 64;
#endif

/* ── Capability Limits ──────────────────────────────────────────────── */

#ifdef MaxCapabilitiesOverride
static constexpr size_t   MaxCapabilities     = MaxCapabilitiesOverride;
#else
static constexpr size_t   MaxCapabilities     = 32;
#endif

/* ── MQTT / Heartbeat ───────────────────────────────────────────────── */

static constexpr uint32_t HeartbeatIntervalSec = 30;
static constexpr uint32_t HeartbeatTimeoutSec  = 120;
static constexpr uint32_t MqttKeepaliveSec     = 60;
static constexpr uint8_t  MqttQos             = 1;

/* ── UUID / ID Field Sizes ──────────────────────────────────────────── */

static constexpr size_t   UuidLen             = 36;  /* "xxxxxxxx-xxxx-..." */
static constexpr size_t   DeviceIdLen        = 32;  /* hex SHA256 prefix  */
static constexpr size_t   MaxNonceLen        = 48;  /* base64 encoded     */
static constexpr size_t   MaxVersionLen      = 16;

/* ── Message Type — Binary Wire Codes ───────────────────────────────── */

enum class MessageType : uint8_t {
    STATE      = 0x01,
    COMMAND    = 0x02,
    ACK        = 0x03,
    HEARTBEAT  = 0x04,
    TELEMETRY  = 0x05,
    OTA        = 0x06,
    ERROR      = 0x07,
    HELLO      = 0x08,
};

/* ── Message Type — String Wire Values ──────────────────────────────── */

struct MessageTypeStr {
    static constexpr char STATE[]     = "state";
    static constexpr char COMMAND[]   = "command";
    static constexpr char ACK[]       = "ack";
    static constexpr char HEARTBEAT[] = "heartbeat";
    static constexpr char TELEMETRY[] = "telemetry";
    static constexpr char OTA[]       = "ota";
    static constexpr char ERROR[]     = "error";
    static constexpr char HELLO[]     = "hello";
};

/* ── MQTT Channel Constants ─────────────────────────────────────────── */

struct Channel {
    static constexpr char STATE[]      = "state";
    static constexpr char CMD[]        = "cmd";
    static constexpr char CMD_ACK[]    = "cmd_ack";
    static constexpr char HELLO[]      = "hello";
    static constexpr char HEARTBEAT[]  = "heartbeat";
    static constexpr char OTA[]        = "ota";
    static constexpr char OTA_STATUS[] = "ota_status";
    static constexpr char TELEMETRY[]  = "telemetry";
};

/* ── ACK Status Values ──────────────────────────────────────────────── */

struct AckStatus {
    static constexpr char EXECUTED[] = "executed";
    static constexpr char FAILED[]   = "failed";
};

/* ── Device Status ──────────────────────────────────────────────────── */

enum class DeviceStatus : uint8_t {
    ONLINE   = 0,
    OFFLINE  = 1,
    UPDATING = 2,
};

/* ── Fixed-length char buffer (no heap) ─────────────────────────────── */

template <size_t N>
struct FixedStr {
    char buf[N + 1];
    uint16_t len;

    FixedStr() : len(0) { buf[0] = '\0'; }

    void set(const char* s) {
        if (!s) { buf[0] = '\0'; len = 0; return; }
        size_t sl = strlen(s);
        if (sl > N) sl = N;
        memcpy(buf, s, sl);
        buf[sl] = '\0';
        len = static_cast<uint16_t>(sl);
    }

    void set(const char* s, size_t sl) {
        if (sl > N) sl = N;
        memcpy(buf, s, sl);
        buf[sl] = '\0';
        len = static_cast<uint16_t>(sl);
    }

    bool equals(const char* s) const {
        return strcmp(buf, s) == 0;
    }

    const char* c_str() const { return buf; }
    bool empty() const { return len == 0; }
    void clear() { buf[0] = '\0'; len = 0; }
};

/* ── Parsed Message Header ─────────────────────────────────────── */

struct MessageHeader {
    FixedStr<MaxVersionLen>    version;
    FixedStr<DeviceIdLen>      device_id;
    FixedStr<UuidLen>           client_id;
    FixedStr<UuidLen>           message_id;
    FixedStr<UuidLen>           request_id;
    FixedStr<UuidLen>           tenant_id;
    int64_t                      timestamp;
    int64_t                      sequence_number;
    FixedStr<MaxNonceLen>      nonce;
    FixedStr<16>                 message_type;
    FixedStr<Sha256HexLen>     payload_hash;
    FixedStr<HmacHexLen>       signature;
    FixedStr<32>                 capability;
    FixedStr<32>                 action;
};

/* ── Parsed Command Payload ─────────────────────────────────────────── */

struct CommandPayload {
    uint16_t       capability_id;
    FixedStr<32>   action;
    /* Raw params JSON kept in frame buffer for handler; offset + length */
    uint16_t       params_offset;
    uint16_t       params_length;
};

/* ── Inbound Frame (holds raw + parsed data) ────────────────────────── */

struct InboundFrame {
    /* Binary header extracted fields */
    MessageType          wire_type;
    uint32_t             json_length;

    /* Parsed JSON header */
    MessageHeader       header;

    /* Command-specific parsed data */
    CommandPayload      command;

    /* Pointer to raw JSON (within frame_buf, NOT owned) */
    const char*          json_ptr;
    uint32_t             json_len;

    /* Pointer to raw params JSON (within json_ptr) */
    const char*          params_ptr;
    uint32_t             params_len;
};

/* ── Outbound Message Build Context ─────────────────────────────────── */

struct OutboundContext {
    const char*  message_type;   /* string wire value */
    const char*  device_id;
    const char*  tenant_id;
    const char*  client_id;
    int64_t      timestamp;      /* Unix epoch milliseconds */
    int64_t      sequence_number;
    /* payload JSON written by caller into frame buffer */
    const char*  payload_json;
    uint32_t     payload_json_len;
};

/* ── Capability Handler Function Pointer ────────────────────────────── */

struct CapabilityResult {
    bool     success;
    int16_t  error_code;    /* 0 = OK */
    char     error_msg[64];
};

using CapabilityHandler = CapabilityResult (*)(
    const char* params_json,
    uint32_t    params_len,
    void*       user_ctx
);

namespace hxtp {

/* ── Capability Registration Entry ──────────────────────────────────── */

struct CapabilityEntry {
    uint16_t            id;
    char                action[32];
    CapabilityHandler   handler;
    void*               user_ctx;
    bool                active;
};

/* ── SDK Configuration ──────────────────────────────────────────────── */

struct Config {
    /* Network */
    const char*  wifi_ssid;
    const char*  wifi_password;

    /* Provisioning Payload / Bootstrap */
    const char*  api_base_url;   /* e.g. "https://cloud.hestialabs.in/api/v1" */
    const char*  device_id;      /* 32-char hex */
    const char*  tenant_id;      /* UUID */
    const char*  device_secret;  /* 64-char hex */
    uint32_t     initial_sequence;

    /* TLS */
    const char*  ca_cert;        /* PEM root CA (required in release builds) */
    bool         verify_server;

    /* Device Metadata */
    const char*  firmware_version;
    const char*  device_type;

    /* Tuning */
    uint32_t     heartbeat_interval_seconds;
    uint32_t     frame_buf_size;
    uint32_t     max_reconnect_delay_ms;

    /* Defaults */
    Config() :
        wifi_ssid(nullptr), wifi_password(nullptr),
        api_base_url(nullptr), device_id(nullptr), tenant_id(nullptr),
        device_secret(nullptr), initial_sequence(0),
        ca_cert(nullptr), verify_server(true),
        firmware_version("0.0.1"), device_type("esp32"),
        heartbeat_interval_seconds(HeartbeatIntervalSec),
        frame_buf_size(FrameBufDefault),
        max_reconnect_delay_ms(60000)
    {}
};

} /* namespace hxtp */

/* ── Platform Abstraction — Storage Interface ───────────────────────── */

struct StorageAdapter {
    bool (*init)(void);
    bool (*read_secret)(uint8_t* out, size_t len);
    bool (*write_secret)(const uint8_t* data, size_t len);
    bool (*read_sequence)(const char* key, int64_t* out);
    bool (*write_sequence)(const char* key, int64_t value);
    bool (*read_device_id)(char* out, size_t max_len);
    bool (*write_device_id)(const char* id);
    bool (*read_param)(const char* key, char* out, size_t max_len);
    bool (*write_param)(const char* key, const char* val);
    bool (*read_ca_cert)(char* out, size_t max_len);
    bool (*write_ca_cert)(const char* cert);
};

/* ── Platform Abstraction — Crypto RNG ──────────────────────────────── */

struct PlatformCrypto {
    bool (*random_bytes)(uint8_t* out, size_t len);
    uint32_t (*get_time_ms)(void);   /* monotonic milliseconds */
    int64_t  (*get_epoch_ms)(void);  /* Unix epoch milliseconds */
};

/* ── Validation Result ──────────────────────────────────────────────── */

enum class ValidationStep : uint8_t {
    VersionCheck      = 1,
    TimestampCheck    = 2,
    PayloadSizeCheck = 3,
    NonceCheck        = 4,
    PayloadHashCheck = 5,
    SequenceCheck     = 6,
    SignatureCheck    = 7,
    Passed             = 0,
};

struct ValidationResult {
    bool                 passed;
    ValidationStep      failed_step;
    const char*          reason;

    static ValidationResult ok() {
        return { true, ValidationStep::Passed, nullptr };
    }

    static ValidationResult fail(ValidationStep step, const char* msg) {
        return { false, step, msg };
    }
};

#endif /* TYPES_H */
