/*
 * HXTP Embedded SDK v1.0
 * Library Build Test Sketch
 *
 * Simple sketch to verify the library compiles and links correctly.
 * For full examples, see examples/ directory.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include <Arduino.h>
#include <HXTP.h>

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n========================================");
    Serial.println("HXTP Embedded SDK v1.0 - Build Test");
    Serial.println("========================================");
    Serial.println("Library compiled successfully.");
    Serial.println("See examples/ directory for full usage.");
    Serial.println("========================================\n");
}

void loop() {
    delay(5000);
    Serial.println("HXTP library ready. See examples/ for implementation.");
}
