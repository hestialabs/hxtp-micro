/*
 * HXTP Micro SDK - Basic Device Example (Zero-Config)
 * 
 * Demonstrates the production-grade onboarding flow:
 *   1. Device starts with EMPTY configuration.
 *   2. SDK detects missing credentials and starts SoftAP Provisioning.
 *   3. User "claims" device via web portal (passing WiFi & secrets).
 *   4. Device reboots, performs Secure Bootstrap, and connects to Cloud.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include "Hxtp.h"

// ---- Global HXTP Client ----
hxtp::Client* hxtpClient = nullptr;

// ---- SDK Event Callbacks ----
void onHxtpStateChange(hxtp::ClientState oldState, hxtp::ClientState newState, void*) {
    Serial.print("[HXTP] State: ");
    Serial.println(hxtpClient->stateStr());

    if (newState == hxtp::ClientState::PROVISIONING) {
        Serial.println("--------------------------------------------------");
        Serial.println("  ACTION REQUIRED: PROVISIONING MODE ACTIVE");
        Serial.println("  Connect to WiFi AP: HXTP-XXXX");
        Serial.println("  Open portal to claim this device.");
        Serial.println("--------------------------------------------------");
    }
}

void onHxtpError(Error err, const char* msg, void*) {
    Serial.printf("[HXTP] ERROR %d: %s\n", static_cast<int>(err), msg ? msg : "Unknown");
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n--- HxTP Zero-Config Device Starting ---");

    // 1. Configure the HXTP Client with Defaults
    // No hardcoded passwords or IDs needed!
    hxtp::Config config;
    config.device_type      = "basic-device";
    config.firmware_version = "1.1.0";
    
    // Default to strict TLS verification (Production Standard)
    config.verify_server    = true; 

    // 2. Initialize the Client
    hxtpClient = new hxtp::Client(config);
    hxtpClient->onStateChange(onHxtpStateChange, nullptr);
    hxtpClient->onError(onHxtpError, nullptr);

    Error err = hxtpClient->begin();
    if (err != Error::OK) {
        Serial.printf("Initialization failed: %d\n", static_cast<int>(err));
        while (true) { delay(1000); }
    }

    // 3. Connect to HxTP Cloud
    // If no credentials exist in storage, this triggers STATE_PROVISIONING
    hxtpClient->connect();
}

void loop() {
    // 4. Run the SDK internal loop continuously
    if (hxtpClient) {
        hxtpClient->loop();
    }
}
