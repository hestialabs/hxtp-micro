
#include <Arduino.h>
#include <Hxtp.h>

void setup() {
    Serial.begin(115200);
    hxtp::Config config;
    config.device_type = "build-test";
    hxtp::Client client(config);
    client.begin();
}

void loop() {
}