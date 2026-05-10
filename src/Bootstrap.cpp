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

BootstrapConfig Bootstrap::perform(const char* api_url) {
    BootstrapConfig config;
    memset(&config, 0, sizeof(config));
    config.mqtt_port = 8883;
    config.heartbeat_interval_seconds = 30;
    config.success = false;

    if (!core_ || !core_->is_initialized() || !core_->is_secret_loaded()) {
        return config;
    }

    const char* base_url = api_url ? api_url : core_->config()->api_base_url;
    if (!base_url) return config;

    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/devices/%s/bootstrap", base_url, core_->device_id());

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
             core_->device_id(),
             core_->tenant_id(),
             core_->client_id(),
             msg_id,
             msg_id,
             (long long)timestamp,
             nonce);

    char signature[HmacHexLen + 1];
    crypto::hmac_sha256_hex(core_->device_secret(), SecretLen,
                            canonical, strlen(canonical), signature);

    /* Execute HTTP Request */
    HTTPClient http;
#ifdef ESP8266
    BearSSL::X509List* tmp_x509 = nullptr;
#endif

    /* Load Root CA if available */
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
        /* If verify requested but no cert found, fail closed */
        Serial.println("[HXTP] ERROR: TLS verification requested but no CA cert found.");
        return config;
    } else {
        /* Insecure mode allowed only if explicitly disabled in config */
        tls_client_->setInsecure();
    }

    http.begin(*tls_client_, url);
    http.addHeader("X-HXTP-Version", VersionString);
    http.addHeader("X-HXTP-Timestamp", String(timestamp));
    http.addHeader("X-HXTP-Nonce", nonce);
    http.addHeader("X-HXTP-Message-ID", msg_id);
    http.addHeader("X-HXTP-Signature", signature);

    int code = http.GET();
    if (code == HTTP_CODE_OK) {
        String body = http.getString();
        const char* json = body.c_str();
        size_t jlen = body.length();

        /* ── Parse Response (Zero-Allocation) ─────────────── */
        char state_str[32];
        char endpoint[128];

        config.activation_state = DeviceActivationState::BOOTSTRAP;

        /* Activation State Mapping */
        if (json_get_string(json, jlen, "activation_state", state_str, sizeof(state_str), nullptr)) {
            if (strcmp(state_str, "active") == 0) {
                config.activation_state = DeviceActivationState::ACTIVE;
                config.success = true;
            } else if (strcmp(state_str, "claimed") == 0) {
                config.activation_state = DeviceActivationState::CLAIMED;
                config.success = true;
            } else if (strcmp(state_str, "pending_claim") == 0) {
                config.activation_state = DeviceActivationState::PENDING_CLAIM;
                config.success = true; 
            } else if (strcmp(state_str, "revoked") == 0) {
                config.activation_state = DeviceActivationState::REVOKED;
                Serial.println("[HXTP] DEVICE REVOKED BY CLOUD");
                config.success = false;
                return config;
            }
        }

        /* 2. MQTT Endpoint */
        if (json_get_string(json, jlen, "mqtt_endpoint", endpoint, sizeof(endpoint), nullptr)) {
            // Parse mqtts://host:port
            const char* host_start = strstr(endpoint, "://");
            host_start = host_start ? host_start + 3 : endpoint;
            
            const char* port_ptr = strchr(host_start, ':');
            if (port_ptr) {
                size_t host_len = port_ptr - host_start;
                if (host_len < sizeof(config.mqtt_host)) {
                    memcpy(config.mqtt_host, host_start, host_len);
                    config.mqtt_host[host_len] = '\0';
                }
                config.mqtt_port = (uint16_t)atoi(port_ptr + 1);
            } else {
                strncpy(config.mqtt_host, host_start, sizeof(config.mqtt_host) - 1);
            }
        }

        /* 3. MQTT Session Token */
        if (json_get_string(json, jlen, "mqtt_session_token", config.mqtt_session_token, sizeof(config.mqtt_session_token), nullptr)) {
            char exp_buf[32];
            if (json_get_string(json, jlen, "session_expiry", exp_buf, sizeof(exp_buf), nullptr)) {
                config.session_expiry_ms = (int64_t)atoll(exp_buf);
            }
        }

        int64_t hb = 30;
        if (json_get_int64(json, jlen, "heartbeat_interval", &hb)) {
            config.heartbeat_interval_seconds = (uint32_t)hb;
        }

        config.success = true;
    }

    http.end();
#ifdef ESP8266
    /* Cleanup temporary trust anchor */
    tls_client_->setTrustAnchors(nullptr);
    if (tmp_x509) delete tmp_x509;
#endif
    return config;
}

} /* namespace hxtp */
