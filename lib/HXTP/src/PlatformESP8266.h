/*
 * HXTP Embedded SDK v1.0
 * ESP8266 Platform — Storage (EEPROM) + Crypto Adapter
 *
 * ESP8266 does not have NVS; uses EEPROM emulation (flash sector).
 * Layout at EEPROM offset 0:
 *   [0]        magic byte (0xA5 = initialized)
 *   [1..32]    device secret (32 bytes)
 *   [33..64]   device ID (32 chars, null-terminated)
 *   [65..72]   outbound sequence (int64, little-endian)
 *   [73..128]  reserved
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_PLATFORM_ESP8266_H
#define HXTP_PLATFORM_ESP8266_H

#include "Types.h"

#ifdef ESP8266

#include <EEPROM.h>
#include <time.h>
#include <sys/time.h>
#include <Arduino.h>

namespace hxtp {
namespace platform {

static constexpr size_t   EEPROM_SIZE          = 128;
static constexpr size_t   EEPROM_MAGIC_OFFSET  = 0;
static constexpr uint8_t  EEPROM_MAGIC_VALUE   = 0xA5;
static constexpr size_t   EEPROM_SECRET_OFFSET = 1;
static constexpr size_t   EEPROM_DEVID_OFFSET  = 33;
static constexpr size_t   EEPROM_SEQ_OFFSET    = 65;

static bool s_eeprom_initialized = false;

/* ── EEPROM Init ────────────────────────────────────────────────────── */

static bool eeprom_storage_init() {
    EEPROM.begin(EEPROM_SIZE);
    s_eeprom_initialized = true;
    return true;
}

/* ── Read Secret ────────────────────────────────────────────────────── */

static bool eeprom_read_secret(uint8_t* out, size_t len) {
    if (!s_eeprom_initialized || len != HXTP_SECRET_LEN) return false;

    uint8_t magic = EEPROM.read(EEPROM_MAGIC_OFFSET);
    if (magic != EEPROM_MAGIC_VALUE) return false;

    for (size_t i = 0; i < len; ++i) {
        out[i] = EEPROM.read(EEPROM_SECRET_OFFSET + i);
    }
    return true;
}

/* ── Write Secret ───────────────────────────────────────────────────── */

static bool eeprom_write_secret(const uint8_t* data, size_t len) {
    if (!s_eeprom_initialized || len != HXTP_SECRET_LEN) return false;

    EEPROM.write(EEPROM_MAGIC_OFFSET, EEPROM_MAGIC_VALUE);
    for (size_t i = 0; i < len; ++i) {
        EEPROM.write(EEPROM_SECRET_OFFSET + i, data[i]);
    }
    return EEPROM.commit();
}

/* ── Read Sequence ──────────────────────────────────────────────────── */

static bool eeprom_read_sequence(const char* key, int64_t* out) {
    (void)key; /* single-device, single sequence */
    if (!s_eeprom_initialized || !out) return false;

    uint8_t magic = EEPROM.read(EEPROM_MAGIC_OFFSET);
    if (magic != EEPROM_MAGIC_VALUE) return false;

    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
        buf[i] = EEPROM.read(EEPROM_SEQ_OFFSET + i);
    }

    /* Little-endian int64 decode */
    *out = static_cast<int64_t>(buf[0])
         | (static_cast<int64_t>(buf[1]) << 8)
         | (static_cast<int64_t>(buf[2]) << 16)
         | (static_cast<int64_t>(buf[3]) << 24)
         | (static_cast<int64_t>(buf[4]) << 32)
         | (static_cast<int64_t>(buf[5]) << 40)
         | (static_cast<int64_t>(buf[6]) << 48)
         | (static_cast<int64_t>(buf[7]) << 56);

    return true;
}

/* ── Write Sequence ─────────────────────────────────────────────────── */

static bool eeprom_write_sequence(const char* key, int64_t value) {
    (void)key;
    if (!s_eeprom_initialized) return false;

    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
        buf[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }

    for (size_t i = 0; i < 8; ++i) {
        EEPROM.write(EEPROM_SEQ_OFFSET + i, buf[i]);
    }
    return EEPROM.commit();
}

/* ── Read Device ID ─────────────────────────────────────────────────── */

static bool eeprom_read_device_id(char* out, size_t max_len) {
    if (!s_eeprom_initialized || max_len < HXTP_DEVICE_ID_LEN + 1) return false;

    uint8_t magic = EEPROM.read(EEPROM_MAGIC_OFFSET);
    if (magic != EEPROM_MAGIC_VALUE) return false;

    for (size_t i = 0; i < HXTP_DEVICE_ID_LEN; ++i) {
        out[i] = static_cast<char>(EEPROM.read(EEPROM_DEVID_OFFSET + i));
    }
    out[HXTP_DEVICE_ID_LEN] = '\0';

    /* Validate: check that it's not all zeros */
    bool all_zero = true;
    for (size_t i = 0; i < HXTP_DEVICE_ID_LEN; ++i) {
        if (out[i] != '\0' && out[i] != 0) { all_zero = false; break; }
    }
    return !all_zero;
}

/* ── Write Device ID ────────────────────────────────────────────────── */

static bool eeprom_write_device_id(const char* id) {
    if (!s_eeprom_initialized || !id) return false;

    EEPROM.write(EEPROM_MAGIC_OFFSET, EEPROM_MAGIC_VALUE);
    size_t idlen = strlen(id);
    if (idlen > HXTP_DEVICE_ID_LEN) idlen = HXTP_DEVICE_ID_LEN;

    for (size_t i = 0; i < idlen; ++i) {
        EEPROM.write(EEPROM_DEVID_OFFSET + i, static_cast<uint8_t>(id[i]));
    }
    /* Pad with nulls */
    for (size_t i = idlen; i < HXTP_DEVICE_ID_LEN; ++i) {
        EEPROM.write(EEPROM_DEVID_OFFSET + i, 0);
    }

    return EEPROM.commit();
}

/* ── Hardware RNG ───────────────────────────────────────────────────── */

static bool esp8266_random_bytes(uint8_t* out, size_t len) {
    if (!out || len == 0) return false;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = RANDOM_REG32;  /* hardware TRNG register (macro from esp8266_peri.h) */
        size_t chunk = (len - i < 4) ? (len - i) : 4;
        memcpy(out + i, &r, chunk);
    }
    return true;
}

/* ── Time ───────────────────────────────────────────────────────────── */

static uint32_t esp8266_get_time_ms() {
    return static_cast<uint32_t>(millis());
}

static int64_t esp8266_get_epoch_ms() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<int64_t>(tv.tv_sec) * 1000LL
         + static_cast<int64_t>(tv.tv_usec / 1000);
}

/* ── Adapter Factories ──────────────────────────────────────────────── */

inline HxtpStorageAdapter create_eeprom_adapter() {
    HxtpStorageAdapter adapter;
    adapter.init            = eeprom_storage_init;
    adapter.read_secret     = eeprom_read_secret;
    adapter.write_secret    = eeprom_write_secret;
    adapter.read_sequence   = eeprom_read_sequence;
    adapter.write_sequence  = eeprom_write_sequence;
    adapter.read_device_id  = eeprom_read_device_id;
    adapter.write_device_id = eeprom_write_device_id;
    return adapter;
}

inline HxtpPlatformCrypto create_esp8266_crypto() {
    HxtpPlatformCrypto pc;
    pc.random_bytes = esp8266_random_bytes;
    pc.get_time_ms  = esp8266_get_time_ms;
    pc.get_epoch_ms = esp8266_get_epoch_ms;
    return pc;
}

} /* namespace platform */
} /* namespace hxtp */

#endif /* ESP8266 */
#endif /* HXTP_PLATFORM_ESP8266_H */
