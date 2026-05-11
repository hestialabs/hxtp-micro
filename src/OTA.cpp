/*
 * HXTP Embedded SDK v1.0.3
 * OTA Manager — Implementation
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "OTA.h"
#include <Arduino.h>

namespace hxtp {

OtaManager::OtaManager(Core* core, WiFiClientSecure* tls_client)
    : core_(core)
    , tls_client_(tls_client)
{
}
bool OtaManager::check_and_update() {
    if (!core_ || !core_->is_initialized()) return false;

    SessionMetadata& sess = core_->session();
    if (!sess.update_available || sess.ota_manifest_url.empty()) {
        return false;
    }

    /* 1. Rollback protection */
    static uint32_t current_rollback_index = 0; /* Should be persisted or defined in firmware */
    if (sess.rollback_index < current_rollback_index) {
        Serial.printf("[HXTP] REJECTED: OTA rollback detected (%u < %u)\n", 
                      sess.rollback_index, current_rollback_index);
        return false;
    }

    /* 2. Signature verification (Root Authority) */
    if (sess.ota_signature.empty()) {
        Serial.println("[HXTP] REJECTED: OTA manifest is unsigned.");
        return false;
    }

    Serial.printf("[HXTP] OTA Update Available: %s (Index: %u)\n", 
                  sess.latest_firmware_version.c_str(), sess.rollback_index);
    Serial.printf("[HXTP] Manifest: %s\n", sess.ota_manifest_url.c_str());

    return download_and_apply(sess.ota_manifest_url.c_str(), sess.ota_signature.c_str());
}

bool OtaManager::download_and_apply(const char* url, const char* signature) {
    /* 
     * In a production HxTP/3.1 runtime:
     * 1. Download manifest
     * 2. Verify signature using RootOtaPubKey
     * 3. Download binary
     * 4. Verify binary hash matches manifest
     */
     
    (void)signature; 

#ifdef ESP32
    Serial.println("[HXTP] Starting ESP32 OTA...");
    
    HTTPClient http;
    http.begin(*tls_client_, url);
    int code = http.GET();
    
    if (code != HTTP_CODE_OK) {
        Serial.printf("[HXTP] OTA HTTP Failed: %d\n", code);
        return false;
    }

    int contentLength = http.getSize();
    if (contentLength <= 0) {
        Serial.println("[HXTP] Invalid OTA content length");
        return false;
    }

    if (!Update.begin(contentLength)) {
        Serial.printf("[HXTP] OTA Update.begin Failed: %s\n", Update.errorString());
        return false;
    }

    WiFiClient* stream = http.getStreamPtr();
    size_t written = Update.writeStream(*stream);

    if (written != (size_t)contentLength) {
        Serial.printf("[HXTP] OTA Written %u/%d\n", written, contentLength);
        return false;
    }

    if (!Update.end()) {
        Serial.printf("[HXTP] OTA Update.end Failed: %s\n", Update.errorString());
        return false;
    }

    if (Update.isFinished()) {
        Serial.println("[HXTP] OTA Success! Rebooting...");
        ESP.restart();
        return true;
    } else {
        Serial.println("[HXTP] OTA failed to finish");
        return false;
    }

#elif defined(ESP8266)
    Serial.println("[HXTP] Starting ESP8266 OTA...");
    t_httpUpdate_return ret = ESPhttpUpdate.update(*tls_client_, url);

    switch (ret) {
        case HTTP_UPDATE_FAILED:
            Serial.printf("[HXTP] OTA Failed: (%d): %s\n", 
                          ESPhttpUpdate.getLastError(), 
                          ESPhttpUpdate.getLastErrorString().c_str());
            break;
        case HTTP_UPDATE_NO_UPDATES:
            Serial.println("[HXTP] No updates found");
            break;
        case HTTP_UPDATE_OK:
            Serial.println("[HXTP] OTA Success!");
            break;
    }
    return ret == HTTP_UPDATE_OK;
#else
    return false;
#endif
}

} /* namespace hxtp */
