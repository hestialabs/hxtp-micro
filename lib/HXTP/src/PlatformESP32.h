/*
 * HXTP Embedded SDK v1.0
 * ESP32 Platform — Transport & Crypto Layer
 *
 * Provides:
 *   - WiFiClientSecure for TLS 1.2+ MQTT
 *   - ESP32 hardware RNG (esp_random)
 *   - NTP-synced epoch time
 *   - HxtpPlatformCrypto adapter
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_PLATFORM_ESP32_H
#define HXTP_PLATFORM_ESP32_H

#include "Types.h"

#ifdef ESP32

#include <esp_system.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <time.h>
#include <sys/time.h>

namespace hxtp {
namespace platform {

/* ── Hardware RNG ───────────────────────────────────────────────────── */

static bool esp32_random_bytes(uint8_t* out, size_t len) {
    if (!out || len == 0) return false;
    esp_fill_random(out, len);
    return true;
}

/* ── Monotonic Milliseconds ─────────────────────────────────────────── */

static uint32_t esp32_get_time_ms() {
    return static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
}

/* ── Epoch Milliseconds (NTP-synced) ────────────────────────────────── */

static int64_t esp32_get_epoch_ms() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<int64_t>(tv.tv_sec) * 1000LL
         + static_cast<int64_t>(tv.tv_usec / 1000);
}

/* ── Platform Crypto Adapter ────────────────────────────────────────── */

inline HxtpPlatformCrypto create_esp32_crypto() {
    HxtpPlatformCrypto pc;
    pc.random_bytes = esp32_random_bytes;
    pc.get_time_ms  = esp32_get_time_ms;
    pc.get_epoch_ms = esp32_get_epoch_ms;
    return pc;
}

/* ── NTP Synchronization Helper ─────────────────────────────────────── */

/**
 * Configure SNTP and wait for time sync.
 * Call after WiFi is connected.
 *
 * @param ntp_server   NTP server hostname (default: "pool.ntp.org")
 * @param timeout_ms   Max wait for sync (default: 10000)
 * @return             true if time synced
 */
bool esp32_sync_time(const char* ntp_server = "pool.ntp.org", uint32_t timeout_ms = 10000);

} /* namespace platform */
} /* namespace hxtp */

#endif /* ESP32 */
#endif /* HXTP_PLATFORM_ESP32_H */
