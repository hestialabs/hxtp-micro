/*
 * HXTP Embedded SDK v1.0
 * ESP32 Platform — NVS Storage Adapter
 *
 * Implements HxtpStorageAdapter using ESP32 Non-Volatile Storage (NVS).
 *
 * Keys stored:
 *   hxtp_secret   → 32-byte device secret (binary)
 *   hxtp_dev_id   → device ID string (32 hex chars)
 *   hxtp_seq_*    → sequence counters (int64)
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_STORAGE_NVS_H
#define HXTP_STORAGE_NVS_H

#include "../core/hxtp_types.h"

#ifdef ESP32

#include <nvs_flash.h>
#include <nvs.h>

namespace hxtp {
namespace platform {

static constexpr char NVS_NAMESPACE[]   = "hxtp";
static constexpr char NVS_KEY_SECRET[]  = "secret";
static constexpr char NVS_KEY_DEV_ID[]  = "dev_id";
static constexpr char NVS_KEY_SEQ_PFX[] = "seq_";

static nvs_handle_t s_nvs_handle = 0;
static bool         s_nvs_open   = false;

/* ── NVS Init ───────────────────────────────────────────────────────── */

static bool nvs_storage_init() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* NVS partition was truncated — erase and retry */
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) return false;

    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &s_nvs_handle);
    if (err != ESP_OK) return false;

    s_nvs_open = true;
    return true;
}

/* ── Read Secret ────────────────────────────────────────────────────── */

static bool nvs_read_secret(uint8_t* out, size_t len) {
    if (!s_nvs_open || len != HXTP_SECRET_LEN) return false;

    size_t required = len;
    esp_err_t err = nvs_get_blob(s_nvs_handle, NVS_KEY_SECRET, out, &required);
    return (err == ESP_OK && required == len);
}

/* ── Write Secret ───────────────────────────────────────────────────── */

static bool nvs_write_secret(const uint8_t* data, size_t len) {
    if (!s_nvs_open || len != HXTP_SECRET_LEN) return false;

    esp_err_t err = nvs_set_blob(s_nvs_handle, NVS_KEY_SECRET, data, len);
    if (err != ESP_OK) return false;

    return nvs_commit(s_nvs_handle) == ESP_OK;
}

/* ── Read Sequence ──────────────────────────────────────────────────── */

static bool nvs_read_sequence(const char* key, int64_t* out) {
    if (!s_nvs_open || !key || !out) return false;

    /* Build NVS key: "seq_" + user key (truncated to fit NVS 15-char limit) */
    char nvs_key[16];
    snprintf(nvs_key, sizeof(nvs_key), "%s%s", NVS_KEY_SEQ_PFX, key);

    int64_t val = 0;
    esp_err_t err = nvs_get_i64(s_nvs_handle, nvs_key, &val);
    if (err != ESP_OK) return false;

    *out = val;
    return true;
}

/* ── Write Sequence ─────────────────────────────────────────────────── */

static bool nvs_write_sequence(const char* key, int64_t value) {
    if (!s_nvs_open || !key) return false;

    char nvs_key[16];
    snprintf(nvs_key, sizeof(nvs_key), "%s%s", NVS_KEY_SEQ_PFX, key);

    esp_err_t err = nvs_set_i64(s_nvs_handle, nvs_key, value);
    if (err != ESP_OK) return false;

    return nvs_commit(s_nvs_handle) == ESP_OK;
}

/* ── Read Device ID ─────────────────────────────────────────────────── */

static bool nvs_read_device_id(char* out, size_t max_len) {
    if (!s_nvs_open || max_len < HXTP_DEVICE_ID_LEN + 1) return false;

    size_t required = max_len;
    esp_err_t err = nvs_get_str(s_nvs_handle, NVS_KEY_DEV_ID, out, &required);
    return (err == ESP_OK);
}

/* ── Write Device ID ────────────────────────────────────────────────── */

static bool nvs_write_device_id(const char* id) {
    if (!s_nvs_open || !id) return false;

    esp_err_t err = nvs_set_str(s_nvs_handle, NVS_KEY_DEV_ID, id);
    if (err != ESP_OK) return false;

    return nvs_commit(s_nvs_handle) == ESP_OK;
}

/* ── Storage Adapter Instance ───────────────────────────────────────── */

inline HxtpStorageAdapter create_nvs_adapter() {
    HxtpStorageAdapter adapter;
    adapter.init           = nvs_storage_init;
    adapter.read_secret    = nvs_read_secret;
    adapter.write_secret   = nvs_write_secret;
    adapter.read_sequence  = nvs_read_sequence;
    adapter.write_sequence = nvs_write_sequence;
    adapter.read_device_id = nvs_read_device_id;
    adapter.write_device_id = nvs_write_device_id;
    return adapter;
}

} /* namespace platform */
} /* namespace hxtp */

#endif /* ESP32 */
#endif /* HXTP_STORAGE_NVS_H */
