# 1 "/tmp/tmpq26bhdeo"
#include <Arduino.h>
# 1 "/home/dedsec/Desktop/hestialabs/SDK/micro/examples/BuildTest/BuildTest.ino"





#include <Arduino.h>
#include <Hxtp.h>
void setup();
void loop();
#line 9 "/home/dedsec/Desktop/hestialabs/SDK/micro/examples/BuildTest/BuildTest.ino"
void setup() {
    Serial.begin(115200);

    hxtp::Config config;
    config.device_type = "build-test";

    hxtp::Client client(config);
    client.begin();
    client.connect();
}

void loop() {

}