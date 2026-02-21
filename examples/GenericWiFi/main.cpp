/*
 * HXTP SDK — Generic WiFi Board Example
 *
 * Minimal skeleton for any Arduino-compatible board with WiFi.
 * Uses compile-time detection to choose WiFi headers.
 *
 * Reports a single "switch" capability and publishes
 * heartbeat telemetry every 60 seconds.
 *
 * Tested with:
 *   - ESP32 DevKit
 *   - ESP8266 NodeMCU
 *   - Wemos D1 Mini
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

/* ── Capability: Switch ──────────────────────────────────────────────── */

static bool switch_state = false;
static const int SWITCH_PIN = 2;               /* GPIO2 — adjust per board */

HxtpCapabilityResult handle_set_switch(const char* p, uint32_t len, void*) {
    HxtpCapabilityResult r{};
    int64_t val = 0;
    if (!hxtp::json_get_int64(p, len, "value", &val)) {
        r.success = false;
        r.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(r.error_msg, sizeof(r.error_msg), "Missing value");
        return r;
    }
    switch_state = val != 0;
    digitalWrite(SWITCH_PIN, switch_state ? HIGH : LOW);
    Serial.printf("[APP] Switch → %s\n", switch_state ? "ON" : "OFF");
    r.success = true;
    return r;
}

/* ── Instance ────────────────────────────────────────────────────────── */

static HXTPConfig config;
static hxtp::HXTPClient* client = nullptr;

void on_state_change(HxtpState state, void*) {
    const char* label = "UNKNOWN";
    switch (state) {
        case HxtpState::DISCONNECTED: label = "DISCONNECTED"; break;
        case HxtpState::CONNECTING:   label = "CONNECTING";   break;
        case HxtpState::CONNECTED:    label = "CONNECTED";    break;
        case HxtpState::PROVISIONING: label = "PROVISIONING"; break;
        case HxtpState::ERROR_STATE:  label = "ERROR";        break;
    }
    Serial.printf("[HXTP] State: %s\n", label);
}

void on_error(HxtpError err, const char* msg, void*) {
    Serial.printf("[HXTP] Error %d: %s\n", static_cast<int>(err), msg ? msg : "");
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n[HXTP] Generic WiFi Board v1.0");

    pinMode(SWITCH_PIN, OUTPUT);
    digitalWrite(SWITCH_PIN, LOW);

    config.wifi_ssid        = WIFI_SSID;
    config.wifi_password    = WIFI_PASS;
    config.mqtt_host        = MQTT_HOST;
    config.mqtt_port        = MQTT_PORT;
    config.ca_cert          = ROOT_CA;
    config.verify_server    = true;
    config.tenant_id        = TENANT_ID;
    config.device_secret    = DEVICE_SECRET;
    config.firmware_version = "1.0.0";
    config.device_type      = "generic-switch";

    client = new hxtp::HXTPClient(config);
    client->onStateChange(on_state_change, nullptr);
    client->onError(on_error, nullptr);

    HxtpError err = client->begin();
    if (err != HxtpError::OK) {
        Serial.printf("[HXTP] FATAL: %s\n", hxtp_error_str(err));
        while (true) delay(1000);
    }

    client->registerCapability(1, "set_switch", handle_set_switch);
    Serial.printf("[HXTP] Device: %s\n", client->deviceId());
    client->connect();
}

static uint32_t last_heartbeat = 0;

void loop() {
    client->loop();

    /* Heartbeat telemetry every 60s */
    if (client->isConnected() && millis() - last_heartbeat >= 60000) {
        last_heartbeat = millis();

        uint32_t uptime_s = millis() / 1000;
        char json[80];
        int n = snprintf(json, sizeof(json),
            "{\"switch\":%s,\"uptime\":%lu}",
            switch_state ? "true" : "false",
            static_cast<unsigned long>(uptime_s));
        if (n > 0) client->publishTelemetry(json, static_cast<uint32_t>(n));
    }
    delay(10);
}
