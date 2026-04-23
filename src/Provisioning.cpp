/*
 * HXTP Embedded SDK v1.0.3
 * Provisioning Manager — Implementation
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "Provisioning.h"
#include "Core.h"
#include "Crypto.h"

namespace hxtp {

Provisioning::Provisioning(StorageAdapter* storage)
    : storage_(storage)
    , server_(80)
    , complete_(false)
{
    memset(ap_ssid_, 0, sizeof(ap_ssid_));
}

void Provisioning::begin(const char* ssid) {
    /* ── Generate Default SSID (HXTP-XXXX) ────────────────── */
    if (!ssid) {
        uint8_t mac[6];
        WiFi.macAddress(mac);
        snprintf(ap_ssid_, sizeof(ap_ssid_), "HXTP-%02X%02X", mac[4], mac[5]);
    } else {
        strncpy(ap_ssid_, ssid, sizeof(ap_ssid_) - 1);
    }

    /* ── Start SoftAP ───────────────────────────────────── */
    WiFi.mode(WIFI_AP);
    WiFi.softAP(ap_ssid_);

    /* ── Setup Web Server ────────────────────────────────── */
    setupRoutes();
    server_.begin();
    
    Serial.print("[HXTP] Provisioning AP active: ");
    Serial.println(ap_ssid_);
}

void Provisioning::end() {
    server_.stop();
    WiFi.softAPdisconnect(true);
}

void Provisioning::loop() {
    server_.handleClient();
}

void Provisioning::setupRoutes() {
    server_.on("/", HTTP_GET, std::bind(&Provisioning::handleRoot, this));
    server_.on("/hxtp/v1/claim", HTTP_POST, std::bind(&Provisioning::handleClaim, this));
    server_.onNotFound(std::bind(&Provisioning::handleNotFound, this));
}

void Provisioning::handleRoot() {
    server_.send(200, "text/plain", "HXTP Provisioning Active");
}

void Provisioning::handleClaim() {
    if (!server_.hasArg("plain")) {
        server_.send(400, "application/json", "{\"error\":\"MISSING_BODY\"}");
        return;
    }

    String body = server_.arg("plain");
    const char* json = body.c_str();
    size_t jlen = body.length();

    char ssid[64];
    char pass[64];
    char tenant[40];
    char device[40];
    char secret_hex[128];

    /* ── Parse Payload using Core JSON Helpers ───────── */
    bool ok = true;
    ok &= json_get_string(json, jlen, "wifi_ssid", ssid, sizeof(ssid), nullptr);
    ok &= json_get_string(json, jlen, "wifi_pass", pass, sizeof(pass), nullptr);
    ok &= json_get_string(json, jlen, "tenant_id", tenant, sizeof(tenant), nullptr);
    ok &= json_get_string(json, jlen, "device_id", device, sizeof(device), nullptr);
    ok &= json_get_string(json, jlen, "secret_hex", secret_hex, sizeof(secret_hex), nullptr);

    if (!ok) {
        server_.send(400, "application/json", "{\"error\":\"INVALID_JSON_OR_FIELDS\"}");
        return;
    }

    /* ── Persist to Storage ────────────────────────────── */
    if (storage_) {
        if (storage_->write_param) {
            storage_->write_param("wifi_ssid", ssid);
            storage_->write_param("wifi_pass", pass);
            storage_->write_param("tenant_id", tenant);
        }
        
        if (storage_->write_device_id) {
            storage_->write_device_id(device);
        }

        /* Decode and store binary secret */
        uint8_t secret_bin[SecretLen];
        size_t dlen = 0;
        if (crypto::hex_decode(secret_hex, strlen(secret_hex), secret_bin, &dlen) && dlen == SecretLen) {
            if (storage_->write_secret) {
                storage_->write_secret(secret_bin, SecretLen);
            }
        } else {
            /* Error decoding secret */
            server_.send(400, "application/json", "{\"error\":\"SECRET_HEX_INVALID\"}");
            return;
        }
    }

    complete_ = true;
    server_.send(200, "application/json", "{\"status\":\"OK\",\"message\":\"PROVISIONED\"}");
    
    Serial.println("[HXTP] Provisioning complete. Rebooting...");
    delay(500);
}

void Provisioning::handleNotFound() {
    server_.send(404, "text/plain", "Not Found");
}

} /* namespace hxtp */
