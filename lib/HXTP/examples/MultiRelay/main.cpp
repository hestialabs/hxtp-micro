/*
 * HXTP SDK — Multi-Capability Node (ESP32, 4 Relays)
 *
 * Demonstrates registering multiple capabilities on a single device:
 *   1. set_relay   — control individual relay by channel (0-3)
 *   2. get_relays  — report all relay states
 *   3. toggle      — flip a relay
 *   4. all_off     — safety kill: turn off all relays
 *
 * Board: ESP32 with 4-channel relay module
 * Pins:  GPIO 16, 17, 18, 19
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include <HXTP.h>

/* ── User Configuration ──────────────────────────────────────────────── */

static const char* WIFI_SSID     = "YOUR_WIFI_SSID";
static const char* WIFI_PASS     = "YOUR_WIFI_PASSWORD";
static const char* MQTT_HOST     = "mqtt.your-server.com";
static const uint16_t MQTT_PORT  = 8883;
static const char* TENANT_ID     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
static const char* DEVICE_SECRET = "YOUR_64_CHAR_HEX_SECRET_HERE____"
                                   "________________________________";
static const char* ROOT_CA = R"(
-----BEGIN CERTIFICATE-----
REPLACE WITH YOUR ROOT CA PEM
-----END CERTIFICATE-----
)";

/* ── Hardware ────────────────────────────────────────────────────────── */

static const uint8_t RELAY_PINS[4] = { 16, 17, 18, 19 };
static bool relay_state[4] = { false, false, false, false };

static void apply_relay(uint8_t ch, bool on) {
    if (ch >= 4) return;
    relay_state[ch] = on;
    digitalWrite(RELAY_PINS[ch], on ? HIGH : LOW);
}

/* ── Capability Handlers ─────────────────────────────────────────────── */

HxtpCapabilityResult handle_set_relay(const char* p, uint32_t len, void*) {
    HxtpCapabilityResult r{};
    int64_t ch = 0, val = 0;
    if (!hxtp::json_get_int64(p, len, "channel", &ch) ||
        !hxtp::json_get_int64(p, len, "value", &val) || ch < 0 || ch > 3) {
        r.success = false;
        r.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(r.error_msg, sizeof(r.error_msg), "Bad channel or value");
        return r;
    }
    apply_relay(static_cast<uint8_t>(ch), val != 0);
    r.success = true;
    return r;
}

HxtpCapabilityResult handle_get_relays(const char*, uint32_t, void* ctx) {
    HxtpCapabilityResult r{};
    auto* client = static_cast<hxtp::HXTPClient*>(ctx);
    char json[64];
    snprintf(json, sizeof(json), "{\"r0\":%d,\"r1\":%d,\"r2\":%d,\"r3\":%d}",
             relay_state[0], relay_state[1], relay_state[2], relay_state[3]);
    client->publishState(json, static_cast<uint32_t>(strlen(json)));
    r.success = true;
    return r;
}

HxtpCapabilityResult handle_toggle(const char* p, uint32_t len, void*) {
    HxtpCapabilityResult r{};
    int64_t ch = 0;
    if (!hxtp::json_get_int64(p, len, "channel", &ch) || ch < 0 || ch > 3) {
        r.success = false;
        r.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(r.error_msg, sizeof(r.error_msg), "Bad channel");
        return r;
    }
    apply_relay(static_cast<uint8_t>(ch), !relay_state[ch]);
    r.success = true;
    return r;
}

HxtpCapabilityResult handle_all_off(const char*, uint32_t, void*) {
    HxtpCapabilityResult r{};
    for (uint8_t i = 0; i < 4; ++i) apply_relay(i, false);
    r.success = true;
    return r;
}

/* ── Instance ────────────────────────────────────────────────────────── */

static HXTPConfig config;
static hxtp::HXTPClient* client = nullptr;

void on_error(HxtpError err, const char* msg, void*) {
    Serial.printf("[HXTP] Error %d: %s\n", static_cast<int>(err), msg ? msg : "");
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n[HXTP] 4-Relay Node Example v1.0");

    for (uint8_t i = 0; i < 4; ++i) {
        pinMode(RELAY_PINS[i], OUTPUT);
        digitalWrite(RELAY_PINS[i], LOW);
    }

    config.wifi_ssid        = WIFI_SSID;
    config.wifi_password    = WIFI_PASS;
    config.mqtt_host        = MQTT_HOST;
    config.mqtt_port        = MQTT_PORT;
    config.ca_cert          = ROOT_CA;
    config.verify_server    = true;
    config.tenant_id        = TENANT_ID;
    config.device_secret    = DEVICE_SECRET;
    config.firmware_version = "1.0.0";
    config.device_type      = "esp32-4relay";

    client = new hxtp::HXTPClient(config);
    client->onError(on_error, nullptr);

    HxtpError err = client->begin();
    if (err != HxtpError::OK) {
        Serial.printf("[HXTP] FATAL: %s\n", hxtp_error_str(err));
        while (true) delay(1000);
    }

    client->registerCapability(1, "set_relay",  handle_set_relay);
    client->registerCapability(2, "get_relays", handle_get_relays, client);
    client->registerCapability(3, "toggle",     handle_toggle);
    client->registerCapability(4, "all_off",    handle_all_off);

    Serial.printf("[HXTP] Device: %s (%zu caps)\n",
                  client->deviceId(), client->core().capabilities().count());
    client->connect();
}

void loop() {
    client->loop();
    delay(10);
}
