/*
 * HXTP Micro SDK - Telemetry Device Example (Zero-Config)
 * 
 * Demonstrates:
 *   1. Zero-config provisioning flow.
 *   2. Periodically publishing sensor telemetry to the cloud.
 *   3. Non-blocking state management.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include "Hxtp.h"

// ---- Global HXTP Client ----
hxtp::Client* hxtpClient = nullptr;

unsigned long lastTelemetryMs = 0;
const unsigned long TELEMETRY_INTERVAL = 30000; // Publish every 30 seconds

// ---- SDK Event Callbacks ----
void onHxtpStateChange(hxtp::ClientState oldState, hxtp::ClientState newState, void*) {
    Serial.printf("[HXTP] State: %s\n", hxtpClient->stateStr());
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n--- HxTP Telemetry Device Starting ---");

    // 1. Configure the HXTP Client
    Config config;
    config.device_type      = "telemetry-node";
    config.firmware_version = "1.0.5";
    config.verify_server    = true; 

    // 2. Initialize the Client
    hxtpClient = new hxtp::Client(config);
    hxtpClient->onStateChange(onHxtpStateChange, nullptr);

    hxtpClient->begin();

    // 3. Start Connection Lifecycle
    hxtpClient->connect();
}

void loop() {
    if (hxtpClient) {
        hxtpClient->loop();
        
        // 4. Publish telemetry when READY
        if (hxtpClient->state() == hxtp::ClientState::READY) {
            if (millis() - lastTelemetryMs >= TELEMETRY_INTERVAL) {
                lastTelemetryMs = millis();
                
                // Simulate sensor reading
                float temp = 22.0 + (random(0, 50) / 10.0);
                float hum  = 40.0 + (random(0, 200) / 10.0);
                
                char payload[128];
                snprintf(payload, sizeof(payload), 
                         "{\"temperature\":%.2f,\"humidity\":%.2f,\"status\":\"nominal\"}", 
                         temp, hum);
                    
                Serial.printf("[Sensor] Data: %s\n", payload);
                
                // publishTelemetry handles framing, signing, and sequence management
                hxtpClient->publishTelemetry(payload, strlen(payload));
            }
        }
    }
}
