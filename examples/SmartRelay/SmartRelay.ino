/*
 * HXTP Micro SDK - Smart Relay Example (Zero-Config)
 * 
 * Demonstrates:
 *   1. Zero-config provisioning flow.
 *   2. Registering a capability handler to toggle a GPIO pin.
 *   3. Strict TLS verification enabled.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include "Hxtp.h"

// ---- Hardware Config ----
static const int RELAY_PIN = 2; // GPIO2 on ESP32

// ---- Global HXTP Client ----
hxtp::Client* hxtpClient = nullptr;

// ---- Capability Handler ----
// This function runs when the cloud sends a 'toggle' command to capability ID 1
CapabilityResult handleToggleRelay(const char* params, uint32_t len, void* user_ctx) {
    CapabilityResult result{};
    
    int64_t target_state = 0;
    // json_get_int64 is a zero-allocation helper provided by the SDK
    if (!hxtp::json_get_int64(params, len, "state", &target_state)) {
        result.success = false;
        result.error_code = 400; // Bad Request
        snprintf(result.error_msg, sizeof(result.error_msg), "Missing 'state' parameter");
        return result;
    }
    
    // Apply state to hardware
    digitalWrite(RELAY_PIN, target_state ? HIGH : LOW);
    Serial.printf("[Relay] Power turned %s\n", target_state ? "ON" : "OFF");
    
    // In a real device, you would publish a 'state' message back to the cloud here
    // to confirm the action succeeded and update the dashboard UI.
    
    result.success = true;
    return result;
}

// ---- SDK Event Callbacks ----
void onHxtpStateChange(hxtp::ClientState oldState, hxtp::ClientState newState, void*) {
    Serial.printf("[HXTP] State: %s\n", hxtpClient->stateStr());
}

void setup() {
    Serial.begin(115200);
    pinMode(RELAY_PIN, OUTPUT);
    digitalWrite(RELAY_PIN, LOW);

    // 1. Configure the HXTP Client
    Config config;
    config.device_type      = "smart-relay";
    config.firmware_version = "1.2.0";
    config.verify_server    = true; // Enforce Root CA validation

    // 2. Initialize the Client
    hxtpClient = new hxtp::Client(config);
    hxtpClient->onStateChange(onHxtpStateChange, nullptr);

    // 3. Register Capability: ID 1, Action "toggle"
    // The server-side dashboard should show a toggle switch for this device.
    hxtpClient->registerCapability(1, "toggle", handleToggleRelay);

    hxtpClient->begin();

    // 4. Start Connection Lifecycle
    hxtpClient->connect();
}

void loop() {
    if (hxtpClient) {
        hxtpClient->loop();
    }
}
