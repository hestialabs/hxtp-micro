/*
 * HXTP Embedded SDK v1.0.3
 * Bootstrap Client — Header
 *
 * Handles operational parameter discovery:
 *   1. Performs Ed25519-signed GET /api/v1/bootstrap
 *   2. Parses MQTT endpoint, heartbeats, and other cloud configs
 *   3. Reconciles with local storage
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include "Types.h"
#include "Core.h"
#include <Arduino.h>

#ifdef ESP32
    #include <HTTPClient.h>
    #include <WiFiClientSecure.h>
#elif defined(ESP8266)
    #include <ESP8266HTTPClient.h>
    #include <WiFiClientSecure.h>
#endif

namespace hxtp {

class Bootstrap {
public:
    Bootstrap(Core* core, WiFiClientSecure* tls_client);

    /**
     * Perform the cloud bootstrap request.
     * @param api_url  Optional override for bootstrap endpoint
     * @return         true if success, session is populated in Core
     */
    bool perform(const char* api_url = nullptr);

private:
    Core* core_;
    WiFiClientSecure* tls_client_;
};

} /* namespace hxtp */

#endif /* BOOTSTRAP_H */
