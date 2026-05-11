/*
 * HXTP Embedded SDK v1.0.3
 * Bootstrap Client — Implementation
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "Bootstrap.h"
#include "Crypto.h"

namespace hxtp {

Bootstrap::Bootstrap(Core* core, WiFiClientSecure* tls_client)
    : core_(core)
    , tls_client_(tls_client)
{
}

bool Bootstrap::perform(const char* api_url) {
    if (!core_ || !core_->is_initialized()) return false;
    if (!core_->ensure_identity()) return false;

    const char* base_url = api_url ? api_url : core_->config()->api_base_url;
    if (!base_url) return false;

    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/devices/%s/bootstrap", base_url, core_->config()->device_uuid);

    /* ── Prepare Headers (HMAC Signing) ──────────────────── */
    char nonce[MaxNonceLen + 1];
    char msg_id[37];
    size_t nlen = 0;
    
    crypto::generate_nonce(nonce, &nlen, core_->platform()->random_bytes);
    crypto::generate_uuid_v4(msg_id, core_->platform()->random_bytes);
    
    int64_t timestamp = core_->platform()->get_epoch_ms();
    
    /* 
     * Canonical HxTP/3.1 Format:
     * version|device_id|tenant_id|client_id|message_id|request_id|sequence|timestamp|nonce|message_type|payload_hash
     */
    char canonical[512];
    snprintf(canonical, sizeof(canonical), "%s|%s|%s|%s|%s|%s|-1|%lld|%s|bootstrap|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             VersionString,
             core_->config()->device_uuid, /* ID is UUID during bootstrap */
             "00000000-0000-0000-0000-000000000000", /* Tenant unknown yet */
             core_->client_id(),
             msg_id,
             msg_id,
             (long long)timestamp,
             nonce);

    char signature[Ed25519SigHexLen + 1];
    uint8_t sig_bin[Ed25519SigLen];
    Error err = crypto::ed25519_sign(
        reinterpret_cast<const uint8_t*>(canonical), strlen(canonical),
        core_->validation_ctx().device_priv_key,
        core_->validation_ctx().device_pub_key,
        sig_bin
    );
    if (err != Error::OK) return false;
    crypto::hex_encode(sig_bin, Ed25519SigLen, signature);

    /* Execute HTTP Request */
    HTTPClient http;
#ifdef ESP8266
    BearSSL::X509List* tmp_x509 = nullptr;
#endif

    /* Load Root CA */
    char ca_cert[4096];
    if (core_->storage() && core_->storage()->read_ca_cert && core_->storage()->read_ca_cert(ca_cert, sizeof(ca_cert))) {
#ifdef ESP32
        tls_client_->setCACert(ca_cert);
#elif defined(ESP8266)
        tmp_x509 = new BearSSL::X509List(ca_cert);
        tls_client_->setTrustAnchors(tmp_x509);
#endif
    } else if (core_->config()->ca_cert) {
#ifdef ESP32
        tls_client_->setCACert(core_->config()->ca_cert);
#elif defined(ESP8266)
        tmp_x509 = new BearSSL::X509List(core_->config()->ca_cert);
        tls_client_->setTrustAnchors(tmp_x509);
#endif
    } else if (core_->config()->verify_server) {
        Serial.println("[HXTP] ERROR: TLS verification requested but no CA cert found.");
        return false;
    } else {
        tls_client_->setInsecure();
    }

    http.begin(*tls_client_, url);
    http.addHeader("X-HXTP-Version", VersionString);
    http.addHeader("X-HXTP-Timestamp", String(timestamp));
    http.addHeader("X-HXTP-Nonce", nonce);
    http.addHeader("X-HXTP-Message-ID", msg_id);
    http.addHeader("X-HXTP-Signature", signature);
    http.addHeader("X-HXTP-Public-Key", core_->ed25519_pub_hex());
    /* Enrollment token from storage (provisioned via SoftAP/dashboard claim) */
    char enrollment_token[256] = {0};
    if (core_->storage() && core_->storage()->read_param) {
        if (core_->storage()->read_param("enrollment_token", enrollment_token, sizeof(enrollment_token))
            && enrollment_token[0] != '\0') {
            http.addHeader("X-HXTP-Enrollment-Token", enrollment_token);
        }
    }

    int code = http.GET();
    bool success = false;
    if (code == HTTP_CODE_OK) {
        String body = http.getString();
        const char* json = body.c_str();
        size_t jlen = body.length();

        SessionMetadata& sess = core_->session();
        char buf[256];

        /* 1. Activation State */
        if (json_get_string(json, jlen, "activation_state", buf, sizeof(buf), nullptr)) {
            if (strcmp(buf, "active") == 0) sess.activation_state = DeviceActivationState::ACTIVE;
            else if (strcmp(buf, "claimed") == 0) sess.activation_state = DeviceActivationState::CLAIMED;
            else if (strcmp(buf, "pending_claim") == 0) sess.activation_state = DeviceActivationState::PENDING_CLAIM;
            else if (strcmp(buf, "revoked") == 0) sess.activation_state = DeviceActivationState::REVOKED;
        }

        /* 2. Device/Tenant Identity */
        if (json_get_string(json, jlen, "device_id", buf, sizeof(buf), nullptr)) sess.device_id.set(buf);
        if (json_get_string(json, jlen, "tenant_id", buf, sizeof(buf), nullptr)) sess.tenant_id.set(buf);

        /* 3. MQTT Endpoint & Token */
        if (json_get_string(json, jlen, "mqtt_endpoint", buf, sizeof(buf), nullptr)) sess.mqtt_endpoint.set(buf);
        if (json_get_string(json, jlen, "mqtt_session_token", buf, sizeof(buf), nullptr)) sess.mqtt_session_token.set(buf);

        /* 4. Heartbeat */
        int64_t hb = 30;
        if (json_get_int64(json, jlen, "heartbeat_interval", &hb)) sess.heartbeat_interval_seconds = (uint32_t)hb;

        /* 5. OTA Metadata */
        if (json_get_string(json, jlen, "ota_manifest_url", buf, sizeof(buf), nullptr)) sess.ota_manifest_url.set(buf);
        if (json_get_string(json, jlen, "ota_signature", buf, sizeof(buf), nullptr)) sess.ota_signature.set(buf);
        if (json_get_string(json, jlen, "latest_firmware", buf, sizeof(buf), nullptr)) sess.latest_firmware_version.set(buf);
        json_get_bool(json, jlen, "update_available", &sess.update_available);

        success = true;
    }

    http.end();
#ifdef ESP8266
    tls_client_->setTrustAnchors(nullptr);
    if (tmp_x509) delete tmp_x509;
#endif
    return success;
}

} /* namespace hxtp */
