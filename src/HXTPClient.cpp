/*
 * HXTP Embedded SDK v1.0
 * Arduino Client Wrapper — Implementation
 *
 * Full connection lifecycle: WiFi → NTP → TLS/MQTT → HELLO → Ready
 * Exponential backoff reconnection. Heartbeat timer.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "HXTPClient.h"
#include <cstring>

namespace hxtp {

/* ── Static Singleton (for PubSubClient callback routing) ───────────── */
HXTPClient* HXTPClient::s_instance_ = nullptr;

/* ── Constructor ────────────────────────────────────────────────────── */

HXTPClient::HXTPClient(const HXTPConfig& config)
    : config_(config)
    , mqtt_client_(tls_client_)
#ifdef ESP8266
    , x509_ca_(nullptr)
#endif
    , state_(HxtpClientState::IDLE)
    , last_heartbeat_ms_(0)
    , last_reconnect_ms_(0)
    , reconnect_delay_ms_(1000)
    , state_enter_ms_(0)
    , state_change_cb_(nullptr)
    , state_change_ctx_(nullptr)
    , error_cb_(nullptr)
    , error_ctx_(nullptr)
    , mqtt_port_(8883)
{
    memset(tx_buf_, 0, sizeof(tx_buf_));
    memset(ack_buf_, 0, sizeof(ack_buf_));
    memset(mqtt_host_, 0, sizeof(mqtt_host_));
    s_instance_ = this;
}

/* ── registerCapability() ────────────────────────────────────────────── */

bool HXTPClient::registerCapability(uint16_t id, const char* action,
                                    CapabilityHandler handler, void* user_ctx)
{
    return core_.capabilities().register_capability(id, action, handler, user_ctx);
}

/* ── begin() ────────────────────────────────────────────────────────── */

HxtpError HXTPClient::begin() {
    /* ── Create platform adapters ────────────────────── */
#ifdef ESP32
    storage_adapter_ = platform::create_nvs_adapter();
    platform_crypto_ = platform::create_esp32_crypto();
#elif defined(ESP8266)
    storage_adapter_ = platform::create_eeprom_adapter();
    platform_crypto_ = platform::create_esp8266_crypto();
#else
    #error "Unsupported platform. Define ESP32 or ESP8266."
#endif

    /* ── Initialize core engine ──────────────────────── */
    HxtpError err = core_.init(&config_, &storage_adapter_, &platform_crypto_);
    if (err != HxtpError::OK) {
        if (error_cb_) error_cb_(err, "Core init failed", error_ctx_);
        set_state(HxtpClientState::ERROR_STATE);
        return err;
    }

    /* ── Configure MQTT ──────────────────────────────── */
    // Server is set later after bootstrap resolves mqtt_host_
    mqtt_client_.setCallback(mqtt_callback_static);
    mqtt_client_.setBufferSize(config_.frame_buf_size > 0 ? config_.frame_buf_size : HXTP_FRAME_BUF_DEFAULT);
    mqtt_client_.setKeepAlive(HXTP_MQTT_KEEPALIVE_S);

    /* ── Configure TLS ───────────────────────────────── */
    if (config_.ca_cert) {
#ifdef ESP32
        tls_client_.setCACert(config_.ca_cert);
#elif defined(ESP8266)
        /* BearSSL: parse PEM into X509List (must stay alive for session) */
        x509_ca_ = new BearSSL::X509List(config_.ca_cert);
        tls_client_.setTrustAnchors(x509_ca_);
#endif
    } else if (!config_.verify_server) {
#if defined(HXTP_DEBUG)
        /*
         * setInsecure() is ONLY permitted in HXTP_DEBUG builds.
         * Production firmware MUST provide a CA certificate.
         * This is a stability contract invariant — never ship insecure TLS.
         */
        tls_client_.setInsecure();
#else
        /* HXTP_RELEASE / HXTP_CONSTRAINED: refuse to run without cert */
        if (error_cb_) error_cb_(HxtpError::CRYPTO_INIT_FAILED,
                                 "TLS: no CA cert in release build", error_ctx_);
        set_state(HxtpClientState::ERROR_STATE);
        return HxtpError::CRYPTO_INIT_FAILED;
#endif
    }

#ifdef ESP8266
    /* BearSSL MFLN: negotiate smaller TLS fragments for low-memory devices */
    tls_client_.setBufferSizes(1536, 512);
#endif

    return HxtpError::OK;
}

/* ── connect() ──────────────────────────────────────────────────────── */

void HXTPClient::connect() {
    if (state_ == HxtpClientState::ERROR_STATE) return;

    if (WiFi.status() == WL_CONNECTED) {
        set_state(HxtpClientState::WIFI_CONNECTED);
    } else {
        WiFi.mode(WIFI_STA);
        WiFi.begin(config_.wifi_ssid, config_.wifi_password);
        set_state(HxtpClientState::WIFI_CONNECTING);
    }
}

/* ── loop() — Main State Machine ────────────────────────────────────── */

void HXTPClient::loop() {
    switch (state_) {
        case HxtpClientState::IDLE:
            break;

        case HxtpClientState::WIFI_CONNECTING:
            tick_wifi_connecting();
            break;

        case HxtpClientState::WIFI_CONNECTED:
            set_state(HxtpClientState::TIME_SYNCING);
            break;

        case HxtpClientState::TIME_SYNCING:
            tick_time_syncing();
            break;

        case HxtpClientState::BOOTSTRAPPING:
            tick_bootstrapping();
            break;

        case HxtpClientState::MQTT_LINKING:
            tick_mqtt_connecting();
            break;

        case HxtpClientState::MQTT_LINKED:
            set_state(HxtpClientState::SUBSCRIBING);
            break;

        case HxtpClientState::SUBSCRIBING:
            tick_subscribing();
            break;

        case HxtpClientState::HELLO_SENT:
            tick_hello();
            break;

        case HxtpClientState::READY:
            tick_ready();
            break;

        case HxtpClientState::RECONNECTING:
            tick_reconnecting();
            break;

        case HxtpClientState::ERROR_STATE:
            break;
    }
}

/* ── State Machine Tick Handlers ────────────────────────────────────── */

void HXTPClient::tick_wifi_connecting() {
    if (WiFi.status() == WL_CONNECTED) {
        set_state(HxtpClientState::WIFI_CONNECTED);
        return;
    }

    /* Timeout after 30 seconds */
    if (millis() - state_enter_ms_ > 30000) {
        if (error_cb_) error_cb_(HxtpError::WIFI_CONNECT_FAILED, "WiFi timeout", error_ctx_);
        set_state(HxtpClientState::RECONNECTING);
    }
}

void HXTPClient::tick_time_syncing() {
#ifdef ESP32
    /* Use ESP32 SNTP helper */
    if (platform::esp32_sync_time("pool.ntp.org", 100)) {
        set_state(HxtpClientState::BOOTSTRAPPING);
        return;
    }
#else
    /* ESP8266: configTime was already set in begin() */
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    struct tm ti;
    localtime_r(&tv.tv_sec, &ti);
    if (ti.tm_year > (2020 - 1900)) {
        set_state(HxtpClientState::BOOTSTRAPPING);
        return;
    }

    /* First call: configure NTP */
    static bool ntp_configured = false;
    if (!ntp_configured) {
        configTime(0, 0, "pool.ntp.org", "time.nist.gov");
        ntp_configured = true;
    }
#endif

    /* Timeout after 15 seconds */
    if (millis() - state_enter_ms_ > 15000) {
        /* Proceed anyway — timestamp validation may reject, but we try */
        set_state(HxtpClientState::BOOTSTRAPPING);
    }
}

void HXTPClient::tick_bootstrapping() {
    if (!config_.api_base_url || !config_.device_id) {
        if (error_cb_) error_cb_(HxtpError::BOOTSTRAP_FAILED, "Missing api_base_url or device_id", error_ctx_);
        set_state(HxtpClientState::ERROR_STATE);
        return;
    }

    char url[256];
    snprintf(url, sizeof(url), "%s/device/%s/bootstrap", config_.api_base_url, config_.device_id);

    HTTPClient http;
#ifdef ESP32
    http.begin(tls_client_, url);
#else
    http.begin(tls_client_, url);
#endif

    int httpCode = http.GET();
    if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_CREATED) {
        String payload = http.getString();
        
        // Naive JSON parse avoiding dynamic memory objects
        // Look for "mqtt_endpoint":"mqtts://host:port"
        // E.g. "mqtt_endpoint":"mqtts://cloud.hestialabs.in:8883"
        int endpoint_idx = payload.indexOf("\"mqtt_endpoint\":\"");
        if (endpoint_idx > 0) {
            int start_idx = endpoint_idx + 17;
            int end_idx = payload.indexOf("\"", start_idx);
            if (end_idx > start_idx) {
                String endpoint = payload.substring(start_idx, end_idx);
                
                // Parse mqtts://host:port
                int proto_end = endpoint.indexOf("://");
                int host_start = (proto_end > 0) ? proto_end + 3 : 0;
                int port_start = endpoint.lastIndexOf(":");
                
                if (port_start > host_start) {
                    String host = endpoint.substring(host_start, port_start);
                    int port = endpoint.substring(port_start + 1).toInt();
                    
                    snprintf(mqtt_host_, sizeof(mqtt_host_), "%s", host.c_str());
                    mqtt_port_ = (uint16_t)port;
                    
                    mqtt_client_.setServer(mqtt_host_, mqtt_port_);
                    set_state(HxtpClientState::MQTT_LINKING);
                } else {
                    snprintf(mqtt_host_, sizeof(mqtt_host_), "%s", endpoint.substring(host_start).c_str());
                    mqtt_port_ = 8883; // default TLS port
                    mqtt_client_.setServer(mqtt_host_, mqtt_port_);
                    set_state(HxtpClientState::MQTT_LINKING);
                }
            } else {
                if (error_cb_) error_cb_(HxtpError::BOOTSTRAP_FAILED, "Invalid endpoint value", error_ctx_);
                set_state(HxtpClientState::RECONNECTING);
            }
        } else {
            // Assume defaults if endpoint not provided in JSON but bootstrap returned 200
            snprintf(mqtt_host_, sizeof(mqtt_host_), "cloud.hestialabs.in");
            mqtt_client_.setServer(mqtt_host_, mqtt_port_);
            set_state(HxtpClientState::MQTT_LINKING);
        }
    } else {
        if (error_cb_) {
            String err = "Bootstrap HTTP Error: " + String(httpCode);
            error_cb_(HxtpError::BOOTSTRAP_FAILED, err.c_str(), error_ctx_);
        }
        set_state(HxtpClientState::RECONNECTING);
    }
    http.end();
}

void HXTPClient::tick_mqtt_connecting() {
    if (mqtt_client_.connected()) {
        set_state(HxtpClientState::MQTT_LINKED);
        return;
    }

    /* Build MQTT client ID */
    char mqtt_cid[48];
    snprintf(mqtt_cid, sizeof(mqtt_cid), "hxtp-%s", core_.device_id());

    bool ok;
    if (config_.device_id && config_.device_secret) {
        ok = mqtt_client_.connect(mqtt_cid, config_.device_id, config_.device_secret);
    } else {
        ok = mqtt_client_.connect(mqtt_cid);
    }

    if (ok) {
        reconnect_delay_ms_ = 1000; /* Reset backoff on success */
        set_state(HxtpClientState::MQTT_LINKED);
    } else {
        if (error_cb_) {
            error_cb_(HxtpError::BROKER_CONNECT_FAILED, "MQTT connect failed", error_ctx_);
        }
        set_state(HxtpClientState::RECONNECTING);
    }
}

void HXTPClient::tick_subscribing() {
    if (subscribe_topics()) {
        set_state(HxtpClientState::HELLO_SENT);

        /* Send HELLO */
        size_t out_len = 0;
        HxtpError err = core_.build_hello(tx_buf_, sizeof(tx_buf_), &out_len);
        if (err == HxtpError::OK && out_len > 0) {
            char topic[128];
            core_.build_topic(HxtpChannel::HELLO, topic, sizeof(topic));
            mqtt_client_.publish(topic, tx_buf_, out_len);
        }
    } else {
        if (error_cb_) error_cb_(HxtpError::BROKER_SUBSCRIBE_FAILED, "Subscribe failed", error_ctx_);
        set_state(HxtpClientState::RECONNECTING);
    }
}

void HXTPClient::tick_hello() {
    mqtt_client_.loop();

    /* Transition to READY after a short delay to allow server to process HELLO.
     * Real production would wait for a HELLO_ACK, but protocol spec allows
     * immediate transition for embedded devices. */
    if (millis() - state_enter_ms_ > 2000) {
        set_state(HxtpClientState::READY);
    }
}

void HXTPClient::tick_ready() {
    /* MQTT keepalive */
    if (!mqtt_client_.loop()) {
        /* Connection lost */
        set_state(HxtpClientState::RECONNECTING);
        return;
    }

    /* Check WiFi */
    if (WiFi.status() != WL_CONNECTED) {
        set_state(HxtpClientState::RECONNECTING);
        return;
    }

    /* Heartbeat timer */
    uint32_t now = millis();
    uint32_t hb_interval = config_.heartbeat_interval_s * 1000;
    if (hb_interval == 0) hb_interval = HXTP_HEARTBEAT_INTERVAL_S * 1000;

    if (now - last_heartbeat_ms_ >= hb_interval) {
        send_heartbeat();
        last_heartbeat_ms_ = now;
    }
}

void HXTPClient::tick_reconnecting() {
    uint32_t now = millis();

    /* Exponential backoff */
    if (now - last_reconnect_ms_ < reconnect_delay_ms_) return;
    last_reconnect_ms_ = now;

    /* Double the delay (capped) */
    reconnect_delay_ms_ *= 2;
    uint32_t max_delay = config_.max_reconnect_delay_ms > 0
                         ? config_.max_reconnect_delay_ms : 60000;
    if (reconnect_delay_ms_ > max_delay) {
        reconnect_delay_ms_ = max_delay;
    }

    /* Check WiFi first */
    if (WiFi.status() != WL_CONNECTED) {
        WiFi.reconnect();
        set_state(HxtpClientState::WIFI_CONNECTING);
    } else {
        set_state(HxtpClientState::MQTT_LINKING);
    }
}

/* ── Heartbeat ──────────────────────────────────────────────────────── */

void HXTPClient::send_heartbeat() {
    size_t out_len = 0;
    HxtpError err = core_.build_heartbeat(tx_buf_, sizeof(tx_buf_), &out_len);
    if (err != HxtpError::OK || out_len == 0) return;

    char topic[128];
    core_.build_topic(HxtpChannel::HEARTBEAT, topic, sizeof(topic));
    mqtt_client_.publish(topic, tx_buf_, out_len);
}

/* ── MQTT Subscriptions ─────────────────────────────────────────────── */

bool HXTPClient::subscribe_topics() {
    char topic[128];

    /* Subscribe to command channel */
    core_.build_topic(HxtpChannel::CMD, topic, sizeof(topic));
    if (!mqtt_client_.subscribe(topic, HXTP_MQTT_QOS)) return false;

    /* Subscribe to OTA channel */
    core_.build_topic(HxtpChannel::OTA, topic, sizeof(topic));
    if (!mqtt_client_.subscribe(topic, HXTP_MQTT_QOS)) return false;

    return true;
}

/* ── MQTT Message Handling ──────────────────────────────────────────── */

void HXTPClient::mqtt_callback_static(char* topic, uint8_t* payload, unsigned int length) {
    if (s_instance_) {
        s_instance_->mqtt_on_message(topic, payload, length);
    }
}

void HXTPClient::mqtt_on_message(char* topic, uint8_t* payload, unsigned int length) {
    if (!payload || length == 0) return;

    /* Process through core engine */
    size_t ack_len = 0;
    HxtpError err = core_.process_inbound(
        topic,
        payload, static_cast<size_t>(length),
        ack_buf_, sizeof(ack_buf_), &ack_len
    );

    /* If ACK was generated, publish it */
    if (ack_len > 0) {
        char ack_topic[128];
        core_.build_topic(HxtpChannel::CMD_ACK, ack_topic, sizeof(ack_topic));
        mqtt_client_.publish(ack_topic, ack_buf_, ack_len);
    }

    /* Report errors */
    if (err != HxtpError::OK && error_cb_) {
        error_cb_(err, hxtp_error_str(err), error_ctx_);
    }
}

/* ── Publish APIs ───────────────────────────────────────────────────── */

HxtpError HXTPClient::publishState(const char* state_json, uint32_t state_len) {
    if (!isConnected()) return HxtpError::PROTOCOL_NOT_READY;

    size_t out_len = 0;
    HxtpError err = core_.build_state(state_json, state_len, tx_buf_, sizeof(tx_buf_), &out_len);
    if (err != HxtpError::OK) return err;

    char topic[128];
    core_.build_topic(HxtpChannel::STATE, topic, sizeof(topic));

    if (!mqtt_client_.publish(topic, tx_buf_, out_len)) {
        return HxtpError::BROKER_PUBLISH_FAILED;
    }

    return HxtpError::OK;
}

HxtpError HXTPClient::publishTelemetry(const char* json, uint32_t json_len) {
    if (!isConnected()) return HxtpError::PROTOCOL_NOT_READY;

    size_t out_len = 0;
    HxtpError err = core_.build_telemetry(json, json_len, tx_buf_, sizeof(tx_buf_), &out_len);
    if (err != HxtpError::OK) return err;

    char topic[128];
    core_.build_topic(HxtpChannel::TELEMETRY, topic, sizeof(topic));

    if (!mqtt_client_.publish(topic, tx_buf_, out_len)) {
        return HxtpError::BROKER_PUBLISH_FAILED;
    }

    return HxtpError::OK;
}

/* ── Disconnect ─────────────────────────────────────────────────────── */

void HXTPClient::disconnect() {
    mqtt_client_.disconnect();
    WiFi.disconnect();
    set_state(HxtpClientState::IDLE);
}

/* ── State Helpers ──────────────────────────────────────────────────── */

bool HXTPClient::isWiFiConnected() const {
    return WiFi.status() == WL_CONNECTED;
}

bool HXTPClient::isMqttConnected() {
    return mqtt_client_.connected();
}

const char* HXTPClient::stateStr() const {
    switch (state_) {
        case HxtpClientState::IDLE:             return "IDLE";
        case HxtpClientState::WIFI_CONNECTING:  return "WIFI_CONNECTING";
        case HxtpClientState::WIFI_CONNECTED:   return "WIFI_CONNECTED";
        case HxtpClientState::TIME_SYNCING:     return "TIME_SYNCING";
        case HxtpClientState::MQTT_LINKING:  return "MQTT_CONNECTING";
        case HxtpClientState::MQTT_LINKED:   return "MQTT_CONNECTED";
        case HxtpClientState::SUBSCRIBING:      return "SUBSCRIBING";
        case HxtpClientState::HELLO_SENT:       return "HELLO_SENT";
        case HxtpClientState::READY:            return "READY";
        case HxtpClientState::RECONNECTING:     return "RECONNECTING";
        case HxtpClientState::ERROR_STATE:      return "ERROR";
        default:                                return "UNKNOWN";
    }
}

void HXTPClient::set_state(HxtpClientState new_state) {
    if (new_state == state_) return;

    HxtpClientState old = state_;
    state_ = new_state;
    state_enter_ms_ = millis();

    if (state_change_cb_) {
        state_change_cb_(old, new_state, state_change_ctx_);
    }
}

void HXTPClient::onStateChange(HxtpStateChangeCallback cb, void* ctx) {
    state_change_cb_ = cb;
    state_change_ctx_ = ctx;
}

void HXTPClient::onError(HxtpErrorCallback cb, void* ctx) {
    error_cb_ = cb;
    error_ctx_ = ctx;
}

} /* namespace hxtp */
