/*
 * hxtp-micro - Basic Device Example (Zero-Config Onboarding)
 * 
 * This example demonstrates the standard Hestia Labs onboarding flow:
 *   1. Device starts with no configuration (blank storage).
 *   2. SDK enters PROVISIONING mode (Starts a SoftAP: HXTP-XXXX).
 *   3. User connects to the AP and claims the device via the web portal.
 *   4. Device reboots, performs Secure Bootstrap, and links to the Cloud.
 * 
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include <Hxtp.h>

// ---- Global hxtp-micro Client ----
hxtp::Client* hxtpClient = nullptr;

// ---- SDK Event Callbacks ----
void onHxtpStateChange(hxtp::ClientState oldState, hxtp::ClientState newState, void*) {
    Serial.print("[HXTP] State Transition: ");
    Serial.println(hxtpClient->stateStr());

    if (newState == hxtp::ClientState::PROVISIONING) {
        Serial.println("--------------------------------------------------");
        Serial.println("  ACTION REQUIRED: PROVISIONING MODE ACTIVE");
        Serial.println("  1. Connect to WiFi AP: HXTP-XXXX");
        Serial.println("  2. Open portal to claim this device.");
        Serial.println("--------------------------------------------------");
    }
}

void onHxtpError(hxtp::Error err, const char* msg, void*) {
    Serial.printf("[HXTP] ERROR %d: %s\n", static_cast<int>(err), msg ? msg : "Unknown");
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n--- hxtp-micro Zero-Config Starting ---");

    // 1. Configure the Client — minimal surface
    // WiFi arrives via SoftAP provisioning. Trust anchors are compiled in.
    hxtp::Config config;
    config.api_base_url = "https://api.hestialabs.in/v1";
    config.device_uuid  = "00000000-0000-0000-0000-000000000000"; // Permanent Hardware UUID

    // 2. Initialize the Client
    hxtpClient = new hxtp::Client(config);
    
    // Register event listeners
    hxtpClient->onStateChange(onHxtpStateChange, nullptr);
    hxtpClient->onError(onHxtpError, nullptr);

    // Prepare internal subsystems
    hxtp::Error err = hxtpClient->begin();
    if (err != hxtp::Error::OK) {
        Serial.printf("Initialization failed: %d\n", static_cast<int>(err));
        while (true) { delay(1000); }
    }

    // 3. Connect to the Lifecycle Engine
    // Automatically handles Provisioning → Bootstrap → Ready
    hxtpClient->connect();
}

void loop() {
    // 4. Run the SDK internal loop
    // Handles keep-alives, heartbeats, and signature verification
    if (hxtpClient) {
        hxtpClient->loop();
    }
}
