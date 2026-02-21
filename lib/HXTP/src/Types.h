/*
 * HXTP Embedded SDK v1.0
 * Core Type Definitions
 *
 * Platform-agnostic types for the HXTP protocol.
 * NO Arduino, NO WiFi, NO MQTT includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_TYPES_H
#define HXTP_TYPES_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include "Config.h"

/* ── Protocol Constants (FROZEN — do not modify) ────────────────────── */

static constexpr uint8_t  HXTP_MAGIC[2]           = { 0x48, 0x58 };   /* "HX" */
static constexpr uint8_t  HXTP_FRAMER_VERSION      = 2;
static constexpr uint8_t  HXTP_PROTOCOL_MAJOR      = 2;
static constexpr uint8_t  HXTP_PROTOCOL_MINOR      = 2;

static constexpr char     HXTP_VERSION_STRING[]    = "HxTP/2.2";
static constexpr char     HXTP_CANONICAL_SEP       = '|';

static constexpr uint8_t  HXTP_HEADER_SIZE         = 8;

/* ── Validation Limits ──────────────────────────────────────────────── */

static constexpr uint32_t HXTP_MAX_MESSAGE_AGE_SEC = 300;   /* 5 minutes */
static constexpr uint32_t HXTP_TIMESTAMP_SKEW_SEC  = 60;    /* 1 minute future */
static constexpr uint32_t HXTP_NONCE_TTL_SEC       = 600;   /* 10 minutes */
static constexpr uint32_t HXTP_MAX_PAYLOAD_BYTES   = 16384; /* 16 KB hard limit */

/* Frame buffer: overridable from Config.h */
#ifdef HXTP_FRAME_BUF_OVERRIDE
static constexpr uint32_t HXTP_FRAME_BUF_DEFAULT   = HXTP_FRAME_BUF_OVERRIDE;
#else
static constexpr uint32_t HXTP_FRAME_BUF_DEFAULT   = 4096;  /* 4 KB default buf */
#endif

/* ── Crypto Constants ───────────────────────────────────────────────── */

static constexpr size_t   HXTP_SHA256_LEN          = 32;
static constexpr size_t   HXTP_SHA256_HEX_LEN      = 64;
static constexpr size_t   HXTP_HMAC_LEN            = 32;
static constexpr size_t   HXTP_HMAC_HEX_LEN        = 64;
static constexpr size_t   HXTP_SECRET_LEN           = 32;
static constexpr size_t   HXTP_SECRET_HEX_LEN       = 64;
static constexpr size_t   HXTP_NONCE_RAW_MIN        = 16;
static constexpr size_t   HXTP_NONCE_B64_MIN        = 22;
static constexpr size_t   HXTP_AES_GCM_IV_LEN       = 12;
static constexpr size_t   HXTP_AES_GCM_TAG_LEN      = 16;
static constexpr size_t   HXTP_AES_KEY_LEN           = 32;

/* ── Nonce Ring Buffer Size ─────────────────────────────────────────── */

#ifdef HXTP_NONCE_CACHE_SIZE_OVERRIDE
static constexpr size_t   HXTP_NONCE_CACHE_SIZE     = HXTP_NONCE_CACHE_SIZE_OVERRIDE;
#else
static constexpr size_t   HXTP_NONCE_CACHE_SIZE     = 64;
#endif

/* ── Capability Limits ──────────────────────────────────────────────── */

#ifdef HXTP_MAX_CAPABILITIES_OVERRIDE
static constexpr size_t   HXTP_MAX_CAPABILITIES     = HXTP_MAX_CAPABILITIES_OVERRIDE;
#else
static constexpr size_t   HXTP_MAX_CAPABILITIES     = 32;
#endif

/* ── MQTT / Heartbeat ───────────────────────────────────────────────── */

static constexpr uint32_t HXTP_HEARTBEAT_INTERVAL_S = 30;
static constexpr uint32_t HXTP_HEARTBEAT_TIMEOUT_S  = 120;
static constexpr uint32_t HXTP_MQTT_KEEPALIVE_S     = 60;
static constexpr uint8_t  HXTP_MQTT_QOS             = 1;

/* ── UUID / ID Field Sizes ──────────────────────────────────────────── */

static constexpr size_t   HXTP_UUID_LEN             = 36;  /* "xxxxxxxx-xxxx-..." */
static constexpr size_t   HXTP_DEVICE_ID_LEN        = 32;  /* hex SHA256 prefix  */
static constexpr size_t   HXTP_MAX_NONCE_LEN        = 48;  /* base64 encoded     */
static constexpr size_t   HXTP_MAX_VERSION_LEN      = 16;

/* ── Message Type — Binary Wire Codes ───────────────────────────────── */

enum class HxtpMessageTypeBin : uint8_t {
    STATE      = 0x01,
    COMMAND    = 0x02,
    ACK        = 0x03,
    HEARTBEAT  = 0x04,
    TELEMETRY  = 0x05,
    OTA        = 0x06,
    ERROR_MSG  = 0x07,
    HELLO      = 0x08,
};

/* ── Message Type — String Wire Values ──────────────────────────────── */

struct HxtpMessageTypeStr {
    static constexpr char STATE[]     = "state";
    static constexpr char COMMAND[]   = "command";
    static constexpr char ACK[]       = "ack";
    static constexpr char HEARTBEAT[] = "heartbeat";
    static constexpr char TELEMETRY[] = "telemetry";
    static constexpr char OTA[]       = "ota";
    static constexpr char ERROR_MSG[] = "error";
    static constexpr char HELLO[]     = "hello";
};

/* ── MQTT Channel Constants ─────────────────────────────────────────── */

struct HxtpChannel {
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

struct HxtpAckStatus {
    static constexpr char EXECUTED[] = "executed";
    static constexpr char FAILED[]   = "failed";
};

/* ── Device Status ──────────────────────────────────────────────────── */

enum class HxtpDeviceStatus : uint8_t {
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

/* ── Parsed HXTP Message Header ─────────────────────────────────────── */

struct HxtpMessageHeader {
    FixedStr<HXTP_MAX_VERSION_LEN>  version;
    FixedStr<HXTP_DEVICE_ID_LEN>    device_id;
    FixedStr<HXTP_UUID_LEN>         client_id;
    FixedStr<HXTP_UUID_LEN>         message_id;
    FixedStr<HXTP_UUID_LEN>         request_id;
    FixedStr<HXTP_UUID_LEN>         tenant_id;
    int64_t                          timestamp;
    int64_t                          sequence_number;
    FixedStr<HXTP_MAX_NONCE_LEN>    nonce;
    FixedStr<16>                     message_type;
    FixedStr<HXTP_SHA256_HEX_LEN>   payload_hash;
    FixedStr<HXTP_HMAC_HEX_LEN>     signature;
};

/* ── Parsed Command Payload ─────────────────────────────────────────── */

struct HxtpCommandPayload {
    uint16_t       capability_id;
    FixedStr<32>   action;
    /* Raw params JSON kept in frame buffer for handler; offset + length */
    uint16_t       params_offset;
    uint16_t       params_length;
};

/* ── Inbound Frame (holds raw + parsed data) ────────────────────────── */

struct HxtpInboundFrame {
    /* Binary header extracted fields */
    HxtpMessageTypeBin  wire_type;
    uint32_t             json_length;

    /* Parsed JSON header */
    HxtpMessageHeader   header;

    /* Command-specific parsed data */
    HxtpCommandPayload  command;

    /* Pointer to raw JSON (within frame_buf, NOT owned) */
    const char*          json_ptr;
    uint32_t             json_len;

    /* Pointer to raw params JSON (within json_ptr) */
    const char*          params_ptr;
    uint32_t             params_len;
};

/* ── Outbound Message Build Context ─────────────────────────────────── */

struct HxtpOutboundContext {
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

struct HxtpCapabilityResult {
    bool     success;
    int16_t  error_code;    /* 0 = OK */
    char     error_msg[64];
};

using CapabilityHandler = HxtpCapabilityResult (*)(
    const char* params_json,
    uint32_t    params_len,
    void*       user_ctx
);

/* ── Capability Registration Entry ──────────────────────────────────── */

struct HxtpCapabilityEntry {
    uint16_t            id;
    char                action[32];
    CapabilityHandler   handler;
    void*               user_ctx;
    bool                active;
};

/* ── SDK Configuration ──────────────────────────────────────────────── */

struct HXTPConfig {
    /* Network */
    const char*  wifi_ssid;
    const char*  wifi_password;

    /* MQTT Broker */
    const char*  mqtt_host;
    uint16_t     mqtt_port;
    const char*  mqtt_username;
    const char*  mqtt_password;

    /* TLS */
    const char*  ca_cert;        /* PEM root CA (required in release builds) */
    bool         verify_server;

    /* Identity */
    const char*  device_id;      /* 32-char hex, or nullptr for auto */
    const char*  tenant_id;      /* UUID */
    const char*  client_id;      /* UUID (correlation) */

    /* Device Secret (hex-encoded 64 chars, or nullptr for NVS lookup) */
    const char*  device_secret;

    /* Device Metadata */
    const char*  firmware_version;
    const char*  device_type;

    /* Tuning */
    uint32_t     heartbeat_interval_s;
    uint32_t     frame_buf_size;
    uint32_t     max_reconnect_delay_ms;

    /* Defaults */
    HXTPConfig() :
        wifi_ssid(nullptr), wifi_password(nullptr),
        mqtt_host(nullptr), mqtt_port(8883),
        mqtt_username(nullptr), mqtt_password(nullptr),
        ca_cert(nullptr), verify_server(true),
        device_id(nullptr), tenant_id(nullptr), client_id(nullptr),
        device_secret(nullptr),
        firmware_version("0.0.1"), device_type("esp32"),
        heartbeat_interval_s(HXTP_HEARTBEAT_INTERVAL_S),
        frame_buf_size(HXTP_FRAME_BUF_DEFAULT),
        max_reconnect_delay_ms(60000)
    {}
};

/* ── Platform Abstraction — Storage Interface ───────────────────────── */

struct HxtpStorageAdapter {
    bool (*init)(void);
    bool (*read_secret)(uint8_t* out, size_t len);
    bool (*write_secret)(const uint8_t* data, size_t len);
    bool (*read_sequence)(const char* key, int64_t* out);
    bool (*write_sequence)(const char* key, int64_t value);
    bool (*read_device_id)(char* out, size_t max_len);
    bool (*write_device_id)(const char* id);
};

/* ── Platform Abstraction — Crypto RNG ──────────────────────────────── */

struct HxtpPlatformCrypto {
    bool (*random_bytes)(uint8_t* out, size_t len);
    uint32_t (*get_time_ms)(void);   /* monotonic milliseconds */
    int64_t  (*get_epoch_ms)(void);  /* Unix epoch milliseconds */
};

/* ── Validation Result ──────────────────────────────────────────────── */

enum class HxtpValidationStep : uint8_t {
    VERSION_CHECK      = 1,
    TIMESTAMP_CHECK    = 2,
    PAYLOAD_SIZE_CHECK = 3,
    NONCE_CHECK        = 4,
    PAYLOAD_HASH_CHECK = 5,
    SEQUENCE_CHECK     = 6,
    SIGNATURE_CHECK    = 7,
    PASSED             = 0,
};

struct HxtpValidationResult {
    bool                 passed;
    HxtpValidationStep   failed_step;
    const char*          reason;

    static HxtpValidationResult ok() {
        return { true, HxtpValidationStep::PASSED, nullptr };
    }

    static HxtpValidationResult fail(HxtpValidationStep step, const char* msg) {
        return { false, step, msg };
    }
};

#endif /* HXTP_TYPES_H */
