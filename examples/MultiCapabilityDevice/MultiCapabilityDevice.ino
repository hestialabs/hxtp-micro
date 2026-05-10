/*
 * hxtp-micro - Multi-Capability Device Example
 * 
 * This example demonstrates:
 *   1. Registering multiple independent capability handlers.
 *   2. Synchronous state feedback within a handler.
 *   3. Handling different parameter types.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include <Hxtp.h>

// ---- Global hxtp-micro Client ----
hxtp::Client* hxtpClient = nullptr;

// Internal System State
bool systemEnabled = true;

// Capability 1: Remote Reset (ID: 10)
hxtp::CapabilityResult handleReset(const char* params, uint32_t len, void* user_ctx) {
    Serial.println("[System] Remote reset triggered. Rebooting in 3 seconds...");
    // Return success ACK first, then hardware reset logic...
    return { true, 0, "" };
}

// Capability 2: Mode Configuration (ID: 11)
hxtp::CapabilityResult handleSetMode(const char* params, uint32_t len, void* user_ctx) {
    int64_t enable = 0;
    if (!hxtp::json_get_int64(params, len, "enabled", &enable)) {
        return { false, 400, "Missing 'enabled' key" };
    }
    
    systemEnabled = (enable != 0);
    Serial.printf("[System] Mode updated to: %s\n", systemEnabled ? "ACTIVE" : "STANDBY");
    
    // Immediate state feedback
    if (hxtpClient && hxtpClient->isConnected()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "{\"enabled\":%s}", systemEnabled ? "true" : "false");
        hxtpClient->publishState(buf, strlen(buf));
    }
    
    return { true, 0, "" };
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n--- hxtp-micro Advanced Hub Starting ---");

    hxtp::Config config;
    config.device_type      = "advanced-hub";
    config.firmware_version = "1.0.3";
    config.verify_server    = true; 

    hxtpClient = new hxtp::Client(config);

    // Register Multiple Capabilities
    hxtpClient->registerCapability(10, "reset",   handleReset);
    hxtpClient->registerCapability(11, "set_mode", handleSetMode);

    hxtpClient->begin();
    hxtpClient->connect();
}

void loop() {
    if (hxtpClient) {
        hxtpClient->loop();
    }
}
