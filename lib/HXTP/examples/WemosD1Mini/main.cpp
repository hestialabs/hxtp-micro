/*
 * HXTP SDK — Wemos D1 Mini Example
 *
 * Temperature + humidity sensor node using DHT11/DHT22.
 * Reports telemetry every 30 seconds. Accepts "set_led" commands.
 *
 * Board: Wemos D1 Mini (ESP8266)
 * Wiring: DHT data → D4 (GPIO 2), built-in LED → D4 (shared)
 *
 * Note: This example keeps the DHT read simple. For production,
 * use a proper DHT library. Raw values shown here for zero-dependency.
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

/* ── Capability ──────────────────────────────────────────────────────── */

HxtpCapabilityResult handle_set_led(const char* p, uint32_t len, void*) {
    HxtpCapabilityResult r{};
    int64_t val = 0;
    if (!hxtp::json_get_int64(p, len, "value", &val)) {
        r.success = false;
        r.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(r.error_msg, sizeof(r.error_msg), "Missing value");
        return r;
    }
    digitalWrite(LED_BUILTIN, val ? LOW : HIGH);
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
    Serial.println("\n[HXTP] Wemos D1 Mini v1.0");

    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, HIGH);

    config.wifi_ssid        = WIFI_SSID;
    config.wifi_password    = WIFI_PASS;
    config.mqtt_host        = MQTT_HOST;
    config.mqtt_port        = MQTT_PORT;
    config.ca_cert          = ROOT_CA;
    config.verify_server    = true;
    config.tenant_id        = TENANT_ID;
    config.device_secret    = DEVICE_SECRET;
    config.firmware_version = "1.0.0";
    config.device_type      = "wemos-d1-mini";

    client = new hxtp::HXTPClient(config);
    client->onError(on_error, nullptr);

    HxtpError err = client->begin();
    if (err != HxtpError::OK) {
        Serial.printf("[HXTP] FATAL: %s\n", hxtp_error_str(err));
        while (true) delay(1000);
    }

    client->registerCapability(1, "set_led", handle_set_led);
    Serial.printf("[HXTP] Device: %s\n", client->deviceId());
    client->connect();
}

static uint32_t last_telemetry = 0;

void loop() {
    client->loop();

    /* Report telemetry every 30s */
    if (client->isConnected() && millis() - last_telemetry >= 30000) {
        last_telemetry = millis();

        /* Simulated sensor read (replace with real DHT library) */
        float temp = 22.5f + (random(0, 100) / 100.0f);
        float humi = 55.0f + (random(0, 200) / 100.0f);

        char json[96];
        int n = snprintf(json, sizeof(json),
            "{\"temp\":%.1f,\"humidity\":%.1f,\"rssi\":%d}",
            temp, humi, WiFi.RSSI());
        if (n > 0) client->publishTelemetry(json, static_cast<uint32_t>(n));
    }
    delay(10);
}
