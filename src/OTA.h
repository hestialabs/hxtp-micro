/*
 * HXTP Embedded SDK v1.0.3
 * OTA Manager — Header
 *
 * Handles automatic firmware updates:
 *   1. Version comparison
 *   2. Manifest signature verification
 *   3. Firmware download & hash verification
 *   4. Platform-specific update execution
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef OTA_H
#define OTA_H

#include "Types.h"
#include "Core.h"

#ifdef ESP32
    #include <HTTPClient.h>
    #include <WiFiClientSecure.h>
    #include <Update.h>
#elif defined(ESP8266)
    #include <ESP8266HTTPClient.h>
    #include <WiFiClientSecure.h>
    #include <ESP8266httpUpdate.h>
#endif

namespace hxtp {

class OtaManager {
public:
    OtaManager(Core* core, WiFiClientSecure* tls_client);

    /**
     * Check if an update is required based on session metadata.
     * @return true if update should proceed
     */
    bool check_and_update();

private:
    bool download_and_apply(const char* url, const char* signature);
    bool verify_firmware(const uint8_t* data, size_t len, const char* signature);

    Core* core_;
    WiFiClientSecure* tls_client_;
};

} /* namespace hxtp */

#endif /* OTA_H */
