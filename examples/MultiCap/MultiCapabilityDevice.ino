/*
 * HXTP Micro SDK - Multi-Capability Device Example (Zero-Config)
 * 
 * Demonstrates a complex node with:
 *   1. Zero-config provisioning & Secure Bootstrap.
 *   2. Multiple independent capability handlers.
 *   3. Synchronous state feedback to the cloud.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include "Hxtp.h"

// ---- Global HXTP Client ----
hxtp::Client* hxtpClient = nullptr;

// Internal System State
bool systemEnabled = true;

// Capability 1: System Reset (ID: 10)
CapabilityResult handleReset(const char* params, uint32_t len, void* user_ctx) {
    CapabilityResult result{};
    Serial.println("[System] Remote reset triggered. Restarting hardware...");
    
    // In a real device, you'd trigger a timer or bit to restart after ACK is sent
    result.success = true;
    return result;
}

// Capability 2: Configure Mode (ID: 11)
CapabilityResult handleSetMode(const char* params, uint32_t len, void* user_ctx) {
    CapabilityResult result{};
    
    int64_t enable = 0;
    if (!hxtp::json_get_int64(params, len, "enabled", &enable)) {
        result.success = false;
        result.error_code = 400;
        snprintf(result.error_msg, sizeof(result.error_msg), "Missing 'enabled' boolean");
        return result;
    }
    
    systemEnabled = (enable != 0);
    Serial.printf("[System] Mode set to: %s\n", systemEnabled ? "ACTIVE" : "STANDBY");
    
    // ── Synchronous Feedback ──────────────────────────────────────────
    // Report the new state back to the cloud immediately so the dashboard
    // reflects the change without waiting for the next heartbeat.
    if (hxtpClient && hxtpClient->state() == hxtp::ClientState::READY) {
        char stateBuf[64];
        snprintf(stateBuf, sizeof(stateBuf), "{\"enabled\":%s}", systemEnabled ? "true" : "false");
        hxtpClient->publishState(stateBuf, strlen(stateBuf));
    }
    
    result.success = true;
    return result;
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n--- HxTP Multi-Capability Hub Starting ---");

    // 1. Configure the HXTP Client
    hxtp::Config config;
    config.device_type      = "advanced-hub";
    config.firmware_version = "2.0.0";
    config.verify_server    = true; 

    // 2. Initialize the Client
    hxtpClient = new hxtp::Client(config);

    // 3. Register Multiple Capabilities
    // These IDs should match the "Capabilities" defined in the Cloud Console
    hxtpClient->registerCapability(10, "reset",   handleReset);
    hxtpClient->registerCapability(11, "set_mode", handleSetMode);

    hxtpClient->begin();

    // 4. Start Lifecycle
    hxtpClient->connect();
}

void loop() {
    if (hxtpClient) {
        hxtpClient->loop();
    }
}
