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

Provisioning::Provisioning(Core* core, StorageAdapter* storage)
    : core_(core)
    , storage_(storage)
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
    server_.on("/wifi/setup", HTTP_POST, std::bind(&Provisioning::handleWifiSetup, this));
    server_.on("/device/info", HTTP_GET, std::bind(&Provisioning::handleInfo, this));
    server_.onNotFound(std::bind(&Provisioning::handleNotFound, this));
}

void Provisioning::handleRoot() {
    server_.send(200, "text/plain", "HXTP Provisioning Active");
}

void Provisioning::handleWifiSetup() {
    if (!server_.hasArg("plain")) {
        server_.send(400, "application/json", "{\"error\":\"MISSING_BODY\"}");
        return;
    }

    String body = server_.arg("plain");
    const char* json = body.c_str();
    size_t jlen = body.length();

    char ssid[64];
    char pass[64];

    /* ── Parse Payload ───────── */
    bool ok = true;
    ok &= json_get_string(json, jlen, "wifi_ssid", ssid, sizeof(ssid), nullptr);
    ok &= json_get_string(json, jlen, "wifi_pass", pass, sizeof(pass), nullptr);

    if (!ok) {
        server_.send(400, "application/json", "{\"error\":\"INVALID_JSON_OR_FIELDS\"}");
        return;
    }

    /* ── Persist to Storage ── */
    if (storage_ && storage_->write_param) {
        storage_->write_param("wifi_ssid", ssid);
        storage_->write_param("wifi_pass", pass);
    }

    complete_ = true;
    server_.send(200, "application/json", "{\"status\":\"OK\",\"message\":\"WIFI_CONFIGURED\"}");
    
    Serial.println("[HXTP] WiFi configured via SoftAP. Rebooting...");
    delay(500);
}

void Provisioning::handleInfo() {
    char token[512];
    bool has_token = core_->generate_claim_token(token, sizeof(token));

    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"device_uuid\":\"%s\","
        "\"board\":\"%s\","
        "\"firmware_version\":\"%s\","
        "\"public_key\":\"%s\","
        "\"claim_token\":\"%s\""
        "}",
        core_->config()->device_uuid ? core_->config()->device_uuid : "unknown",
        core_->descriptor().board_name ? core_->descriptor().board_name : "",
        core_->descriptor().sdk_version ? core_->descriptor().sdk_version : "",
        core_->ed25519_pub_hex(),
        has_token ? token : ""
    );
    server_.send(200, "application/json", json);
}

void Provisioning::handleNotFound() {
    server_.send(404, "text/plain", "Not Found");
}

} /* namespace hxtp */
