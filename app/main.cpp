/*
 * HXTP Embedded SDK — Basic Node Example (PlatformIO)
 *
 * Demonstrates:
 *   - SDK initialization with config
 *   - Capability registration (LED control)
 *   - Connection to HXTP Authority
 *   - State reporting
 *   - Telemetry publishing
 *
 * Target: ESP32-S3 (primary), ESP32, ESP8266
 *
 * Build:
 *   pio run -e esp32s3
 *   pio run -e esp32
 *   pio run -e esp8266
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include <HXTP.h>

/* ═══════════════════════════════════════════════════════════════════
 *  Configuration — CHANGE THESE VALUES
 * ═══════════════════════════════════════════════════════════════════ */

static const char* WIFI_SSID     = "YOUR_WIFI_SSID";
static const char* WIFI_PASS     = "YOUR_WIFI_PASSWORD";

static const char* MQTT_HOST     = "mqtt.your-server.com";
static const uint16_t MQTT_PORT  = 8883;

static const char* TENANT_ID     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
static const char* DEVICE_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/* Root CA certificate for TLS verification */
static const char* ROOT_CA = R"(
-----BEGIN CERTIFICATE-----
MIIBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... paste your root CA here ...
-----END CERTIFICATE-----
)";

/* ═══════════════════════════════════════════════════════════════════
 *  Hardware Configuration
 * ═══════════════════════════════════════════════════════════════════ */

static const int LED_PIN = 2;  /* Built-in LED on most ESP32 boards */

/* ═══════════════════════════════════════════════════════════════════
 *  Capability Handlers
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Handler for "set_pin" command.
 * Expects params: {"pin": <int>, "value": <0|1>}
 */
HxtpCapabilityResult handle_set_pin(
    const char* params_json,
    uint32_t params_len,
    void* user_ctx)
{
    (void)user_ctx;

    HxtpCapabilityResult result;
    memset(&result, 0, sizeof(result));

    /* Parse pin and value from params JSON */
    int64_t pin = 0, value = 0;
    bool has_pin   = hxtp::json_get_int64(params_json, params_len, "pin", &pin);
    bool has_value = hxtp::json_get_int64(params_json, params_len, "value", &value);

    if (!has_pin || !has_value) {
        result.success    = false;
        result.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(result.error_msg, sizeof(result.error_msg), "Missing pin or value");
        return result;
    }

    /* Validate pin range */
    if (pin < 0 || pin > 48) {
        result.success    = false;
        result.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(result.error_msg, sizeof(result.error_msg), "Pin out of range");
        return result;
    }

    /* Execute */
    pinMode(static_cast<uint8_t>(pin), OUTPUT);
    digitalWrite(static_cast<uint8_t>(pin), value ? HIGH : LOW);

    Serial.printf("[HXTP] set_pin: pin=%lld value=%lld\n",
                  static_cast<long long>(pin), static_cast<long long>(value));

    result.success = true;
    result.error_code = 0;
    return result;
}

/**
 * Handler for "get_status" command.
 * Returns device status info.
 */
HxtpCapabilityResult handle_get_status(
    const char* params_json,
    uint32_t params_len,
    void* user_ctx)
{
    (void)params_json;
    (void)params_len;
    (void)user_ctx;

    HxtpCapabilityResult result;
    memset(&result, 0, sizeof(result));

    Serial.println("[HXTP] get_status executed");

    result.success = true;
    result.error_code = 0;
    return result;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Callbacks
 * ═══════════════════════════════════════════════════════════════════ */

void on_state_change(
    hxtp::HxtpClientState old_state,
    hxtp::HxtpClientState new_state,
    void* ctx)
{
    (void)old_state;
    hxtp::HXTPClient* client = static_cast<hxtp::HXTPClient*>(ctx);
    Serial.printf("[HXTP] State: %s -> %s\n",
                  client->stateStr(), client->stateStr());
}

void on_error(HxtpError err, const char* msg, void* ctx) {
    (void)ctx;
    Serial.printf("[HXTP] Error: %s — %s\n", hxtp_error_str(err), msg ? msg : "");
}

/* ═══════════════════════════════════════════════════════════════════
 *  SDK Instance
 * ═══════════════════════════════════════════════════════════════════ */

static HXTPConfig config;
static hxtp::HXTPClient* client = nullptr;

/* ═══════════════════════════════════════════════════════════════════
 *  Arduino setup()
 * ═══════════════════════════════════════════════════════════════════ */

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n[HXTP] Basic Node Example v1.0 (PlatformIO)");

    /* Configure LED */
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);

    /* ── Build config ────────────────────────────────── */
    config.wifi_ssid     = WIFI_SSID;
    config.wifi_password = WIFI_PASS;
    config.mqtt_host     = MQTT_HOST;
    config.mqtt_port     = MQTT_PORT;
    config.ca_cert       = ROOT_CA;
    config.verify_server = true;
    config.tenant_id     = TENANT_ID;
    config.device_secret = DEVICE_SECRET;
    config.firmware_version = "1.0.0";
    config.device_type   = "esp32-basic-node";

    /* ── Create client ───────────────────────────────── */
    client = new hxtp::HXTPClient(config);

    /* ── Register callbacks ──────────────────────────── */
    client->onStateChange(on_state_change, client);
    client->onError(on_error, nullptr);

    /* ── Initialize ──────────────────────────────────── */
    HxtpError err = client->begin();
    if (err != HxtpError::OK) {
        Serial.printf("[HXTP] FATAL: begin() failed: %s\n", hxtp_error_str(err));
        while (1) { delay(1000); }
    }

    /* ── Register capabilities ───────────────────────── */
    client->registerCapability(1, "set_pin",    handle_set_pin);
    client->registerCapability(2, "get_status", handle_get_status);

    Serial.printf("[HXTP] Device ID: %s\n", client->deviceId());
    Serial.printf("[HXTP] Registered %zu capabilities\n",
                  client->core().capabilities().count());

    /* ── Start connection ────────────────────────────── */
    client->connect();
}

/* ═══════════════════════════════════════════════════════════════════
 *  Arduino loop()
 * ═══════════════════════════════════════════════════════════════════ */

/* Telemetry timer */
static uint32_t last_telemetry_ms = 0;
static const uint32_t TELEMETRY_INTERVAL_MS = 60000; /* 1 minute */

void loop() {
    /* ── Tick the SDK ────────────────────────────────── */
    client->loop();

    /* ── Periodic telemetry ──────────────────────────── */
    if (client->isConnected()) {
        uint32_t now = millis();
        if (now - last_telemetry_ms >= TELEMETRY_INTERVAL_MS) {
            last_telemetry_ms = now;

            /* Build telemetry JSON */
            char json[128];
            int len = snprintf(json, sizeof(json),
                "{\"uptime_ms\":%lu,\"free_heap\":%lu,\"rssi\":%d}",
                static_cast<unsigned long>(millis()),
                static_cast<unsigned long>(ESP.getFreeHeap()),
                WiFi.RSSI()
            );

            if (len > 0) {
                HxtpError err = client->publishTelemetry(json, static_cast<uint32_t>(len));
                if (err == HxtpError::OK) {
                    Serial.println("[HXTP] Telemetry sent");
                }
            }
        }
    }

    /* Small yield to prevent WDT */
    delay(10);
}
