/*
 * HXTP Embedded SDK v1.0.3
 * Provisioning Manager — Header
 *
 * Handles zero-config onboarding:
 *   1. Starts SoftAP (HXTP-XXXX)
 *   2. Runs WebServer on port 80
 *   3. Accepts POST /hxtp/v1/claim with WiFi and HxTP credentials
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef PROVISIONING_H
#define PROVISIONING_H

#include "Types.h"
#include <Arduino.h>

#ifdef ESP32
    #include <WiFi.h>
    #include <WebServer.h>
#elif defined(ESP8266)
    #include <ESP8266WiFi.h>
    #include <ESP8266WebServer.h>
#endif

namespace hxtp {

class Provisioning {
public:
    explicit Provisioning(StorageAdapter* storage);

    /**
     * Start the provisioning SoftAP and WebServer.
     * @param ssid  Custom AP SSID (optional, defaults to HXTP-{mac})
     */
    void begin(const char* ssid = nullptr);

    /**
     * Stop the provisioning services and cleanup.
     */
    void end();

    /**
     * Tick the web server. Call in the main loop.
     */
    void loop();

    /**
     * Returns true if provisioning has successfully completed.
     */
    bool isComplete() const { return complete_; }

private:
    void setupRoutes();
    void handleRoot();
    void handleClaim();
    void handleNotFound();

    StorageAdapter* storage_;
#ifdef ESP32
    WebServer server_;
#elif defined(ESP8266)
    ESP8266WebServer server_;
#endif
    bool complete_;
    char ap_ssid_[32];
};

} /* namespace hxtp */

#endif /* PROVISIONING_H */
