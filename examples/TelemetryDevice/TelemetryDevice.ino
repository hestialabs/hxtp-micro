/*
 * hxtp-micro - Telemetry Device Example (Sensor Data Publishing)
 * 
 * This example demonstrates:
 *   1. Periodic publishing of sensor data (telemetry).
 *   2. Automatic signature and sequence management.
 *   3. Non-blocking state-aware execution.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include <Hxtp.h>

// ---- Global hxtp-micro Client ----
hxtp::Client* hxtpClient = nullptr;

unsigned long lastTelemetryMs = 0;
const unsigned long TELEMETRY_INTERVAL = 60000; // Publish every 1 minute

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n--- hxtp-micro Telemetry Node Starting ---");

    // 1. Configure the Client
    hxtp::Config config;
    config.device_type      = "sensor-node";
    config.firmware_version = "1.0.3";
    config.verify_server    = true; 

    // 2. Initialize the Client
    hxtpClient = new hxtp::Client(config);
    hxtpClient->begin();

    // 3. Start Connection Lifecycle
    hxtpClient->connect();
}

void loop() {
    if (hxtpClient) {
        hxtpClient->loop();
        
        // 4. Publish telemetry when READY
        if (hxtpClient->isConnected()) {
            if (millis() - lastTelemetryMs >= TELEMETRY_INTERVAL) {
                lastTelemetryMs = millis();
                
                // Simulate sensor reading
                float temp = 22.0 + (random(0, 50) / 10.0);
                float hum  = 40.0 + (random(0, 200) / 10.0);
                
                char payload[128];
                snprintf(payload, sizeof(payload), 
                         "{\"temp\":%.2f,\"hum\":%.2f,\"unit\":\"C\"}", 
                         temp, hum);
                    
                Serial.printf("[Sensor] Data: %s\n", payload);
                
                // publishTelemetry handles deterministic framing and HMAC signing
                hxtpClient->publishTelemetry(payload, strlen(payload));
            }
        }
    }
}
