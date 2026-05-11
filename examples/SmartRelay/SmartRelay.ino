/*
 * hxtp-micro - Smart Relay Example (Command Handling)
 * 
 * This example demonstrates:
 *   1. Registering a capability handler for remote actions.
 *   2. Zero-allocation JSON parsing of command parameters.
 *   3. Hardware control (GPIO) via cloud commands.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include <Hxtp.h>

// ---- Hardware Config ----
static const int RELAY_PIN = 2; // GPIO2 on most ESP32 boards

// ---- Global hxtp-micro Client ----
hxtp::Client* hxtpClient = nullptr;

// ---- Capability Handler ----
// This function runs when the cloud sends a 'toggle' command
hxtp::CapabilityResult handleToggleRelay(const char* params, uint32_t len, void* user_ctx) {
    hxtp::CapabilityResult result{false, 0, ""};
    
    int64_t target_state = 0;
    // hxtp::json_get_int64 is a zero-allocation helper provided by the SDK
    if (!hxtp::json_get_int64(params, len, "state", &target_state)) {
        result.success = false;
        result.error_code = 400; 
        strncpy(result.error_msg, "Missing 'state' param", sizeof(result.error_msg));
        return result;
    }
    
    // Apply state to hardware
    digitalWrite(RELAY_PIN, target_state ? HIGH : LOW);
    Serial.printf("[Relay] Power changed to %s\n", target_state ? "ON" : "OFF");
    
    // Feedback: Report new state back to the cloud
    if (hxtpClient) {
        char stateBuf[32];
        snprintf(stateBuf, sizeof(stateBuf), "{\"power\":%lld}", target_state);
        hxtpClient->publishState(stateBuf, strlen(stateBuf));
    }
    
    result.success = true;
    return result;
}

void setup() {
    Serial.begin(115200);
    pinMode(RELAY_PIN, OUTPUT);
    digitalWrite(RELAY_PIN, LOW);

    // 1. Configure the Client
    hxtp::Config config;
    config.api_base_url = "https://api.hestialabs.in/v1";
    config.device_uuid  = "00000000-0000-0000-0000-000000000000";

    // 2. Initialize the Client
    hxtpClient = new hxtp::Client(config);

    // 3. Register Capability: ID 1, Action "toggle"
    hxtpClient->registerCapability(1, "toggle", handleToggleRelay);

    hxtpClient->begin();

    // 4. Start Lifecycle
    hxtpClient->connect();
}

void loop() {
    if (hxtpClient) {
        hxtpClient->loop();
    }
}
