/*
 * hxtp-micro - Build Verification Test
 * 
 * Used for CI/CD build checks to ensure the SDK compiles correctly.
 */
#include <Arduino.h>
#include <Hxtp.h>

void setup() {
    Serial.begin(115200);
    
    hxtp::Config config;
    config.device_type = "build-test";
    
    hxtp::Client client(config);
    client.begin();
    client.connect();
}

void loop() {
    // Basic loop check
}
