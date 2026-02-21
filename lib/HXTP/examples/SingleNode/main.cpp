/*
 * HXTP SDK — Single Node Example (ESP32)
 *
 * Demonstrates the minimal setup for an HXTP-connected ESP32 device
 * with LED control and telemetry reporting.
 *
 * Board: Any ESP32 (DevKit, S3, C3)
 *
 * Install:
 *   pio lib install "HXTP"
 *   pio lib install "PubSubClient"
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

static const int LED_PIN = 2;

/* ── Capability Handler ──────────────────────────────────────────────── */

HxtpCapabilityResult handle_set_pin(const char* params, uint32_t len, void*) {
    HxtpCapabilityResult r{};
    int64_t pin = 0, value = 0;

    if (!hxtp::json_get_int64(params, len, "pin", &pin) ||
        !hxtp::json_get_int64(params, len, "value", &value)) {
        r.success = false;
        r.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(r.error_msg, sizeof(r.error_msg), "Missing pin or value");
        return r;
    }

    pinMode(static_cast<uint8_t>(pin), OUTPUT);
    digitalWrite(static_cast<uint8_t>(pin), value ? HIGH : LOW);
    r.success = true;
    return r;
}

/* ── Callbacks ───────────────────────────────────────────────────────── */

void on_error(HxtpError err, const char* msg, void*) {
    Serial.printf("[HXTP] Error %d: %s\n", static_cast<int>(err), msg ? msg : "");
}

/* ── Instance ────────────────────────────────────────────────────────── */

static HXTPConfig config;
static hxtp::HXTPClient* client = nullptr;

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n[HXTP] Single Node Example v1.0");

    pinMode(LED_PIN, OUTPUT);

    config.wifi_ssid        = WIFI_SSID;
    config.wifi_password    = WIFI_PASS;
    config.mqtt_host        = MQTT_HOST;
    config.mqtt_port        = MQTT_PORT;
    config.ca_cert          = ROOT_CA;
    config.verify_server    = true;
    config.tenant_id        = TENANT_ID;
    config.device_secret    = DEVICE_SECRET;
    config.firmware_version = "1.0.0";
    config.device_type      = "esp32-single-node";

    client = new hxtp::HXTPClient(config);
    client->onError(on_error, nullptr);

    HxtpError err = client->begin();
    if (err != HxtpError::OK) {
        Serial.printf("[HXTP] FATAL: %s\n", hxtp_error_str(err));
        while (true) delay(1000);
    }

    client->registerCapability(1, "set_pin", handle_set_pin);
    Serial.printf("[HXTP] Device: %s\n", client->deviceId());
    client->connect();
}

static uint32_t last_telemetry = 0;

void loop() {
    client->loop();

    if (client->isConnected() && millis() - last_telemetry >= 60000) {
        last_telemetry = millis();
        char json[96];
        int n = snprintf(json, sizeof(json),
            "{\"uptime_ms\":%lu,\"heap\":%lu,\"rssi\":%d}",
            (unsigned long)millis(), (unsigned long)ESP.getFreeHeap(), WiFi.RSSI());
        if (n > 0) client->publishTelemetry(json, static_cast<uint32_t>(n));
    }
    delay(10);
}
