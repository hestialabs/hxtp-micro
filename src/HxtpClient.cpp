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

#include "HxtpClient.h"
#include <cstring>

namespace hxtp {

/* ── Static Singleton (for PubSubClient callback routing) ───────────── */
Client* Client::s_instance_ = nullptr;

/* ── Constructor ────────────────────────────────────────────────────── */

Client::Client(const Config& config)
    : config_(config)
    , mqtt_port_(8883)
    , core_()
    , storage_adapter_({})
    , platform_crypto_({})
    , provisioning_(&storage_adapter_)
    , bootstrap_(&core_, &tls_client_)
    , mqtt_client_(tls_client_)
#ifdef ESP8266
    , x509_ca_(nullptr)
#endif
    , state_(ClientState::IDLE)
    , last_heartbeat_ms_(0)
    , last_reconnect_ms_(0)
    , reconnect_delay_ms_(1000)
    , state_enter_ms_(0)
    , state_change_cb_(nullptr)
    , state_change_ctx_(nullptr)
    , error_cb_(nullptr)
    , error_ctx_(nullptr)
{
    memset(tx_buf_, 0, sizeof(tx_buf_));
    memset(ack_buf_, 0, sizeof(ack_buf_));
    memset(mqtt_host_, 0, sizeof(mqtt_host_));
    s_instance_ = this;
}

/* ── registerCapability() ────────────────────────────────────────────── */

bool Client::registerCapability(uint16_t id, const char* action,
                                    CapabilityHandler handler, void* user_ctx)
{
    return core_.capabilities().register_capability(id, action, handler, user_ctx);
}

/* ── begin() ────────────────────────────────────────────────────────── */

Error Client::begin() {
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
    Error err = core_.init(&config_, &storage_adapter_, &platform_crypto_);
    if (err != Error::OK) {
        if (error_cb_) error_cb_(err, "Core init failed", error_ctx_);
        set_state(ClientState::ERROR_STATE);
        return err;
    }

    /* ── Configure MQTT ──────────────────────────────── */
    // Server is set later after bootstrap resolves mqtt_host_
    mqtt_client_.setCallback(mqtt_callback_static);
    mqtt_client_.setBufferSize(config_.frame_buf_size > 0 ? config_.frame_buf_size : FrameBufDefault);
    mqtt_client_.setKeepAlive(MqttKeepaliveSec);

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
        if (error_cb_) error_cb_(Error::CRYPTO_INIT_FAILED,
                                 "TLS: no CA cert in release build", error_ctx_);
        set_state(ClientState::ERROR_STATE);
        return Error::CRYPTO_INIT_FAILED;
#endif
    }

#ifdef ESP8266
    /* BearSSL MFLN: negotiate smaller TLS fragments for low-memory devices */
    tls_client_.setBufferSizes(1536, 512);
#endif

    return Error::OK;
}

/* ── connect() ──────────────────────────────────────────────────────── */

void Client::connect() {
    if (state_ == ClientState::ERROR_STATE) return;

    /* ── 1. Check if we need provisioning ──────────────── */
    char saved_ssid[64] = {0};
    bool has_wifi = (config_.wifi_ssid && config_.wifi_ssid[0] != '\0');
    
    if (!has_wifi && storage_adapter_.read_param) {
        has_wifi = storage_adapter_.read_param("wifi_ssid", saved_ssid, sizeof(saved_ssid));
    }

    if (!has_wifi) {
        provisioning_.begin();
        set_state(ClientState::PROVISIONING);
        return;
    }

    /* ── 2. Standard Connect Flow ──────────────────────── */
    
    /* Load Root CA for strict verification */
    char ca_cert[4096];
    if (storage_adapter_.read_ca_cert(ca_cert, sizeof(ca_cert))) {
        tls_client_.setCACert(ca_cert);
    } else if (config_.ca_cert) {
        tls_client_.setCACert(config_.ca_cert);
    } else if (config_.verify_server) {
        /* Fail closed if verification requested but no cert found */
        Serial.println("[HXTP] ERROR: TLS verification requested but no CA cert found.");
        set_state(ClientState::ERROR_STATE);
        return;
    } else {
        tls_client_.setInsecure();
    }

    if (WiFi.status() == WL_CONNECTED) {
        set_state(ClientState::WIFI_CONNECTED);
    } else {
        WiFi.mode(WIFI_STA);
        if (saved_ssid[0] != '\0') {
            char saved_pass[64] = {0};
            storage_adapter_.read_param("wifi_pass", saved_pass, sizeof(saved_pass));
            WiFi.begin(saved_ssid, saved_pass);
        } else {
            WiFi.begin(config_.wifi_ssid, config_.wifi_password);
        }
        set_state(ClientState::WIFI_CONNECTING);
    }
}

/* ── loop() — Main State Machine ────────────────────────────────────── */

void Client::loop() {
    switch (state_) {
        case ClientState::IDLE:
            break;

        case ClientState::PROVISIONING:
            tick_provisioning();
            break;

        case ClientState::WIFI_CONNECTING:
            tick_wifi_connecting();
            break;

        case ClientState::WIFI_CONNECTED:
            set_state(ClientState::TIME_SYNCING);
            break;

        case ClientState::TIME_SYNCING:
            tick_time_syncing();
            break;

        case ClientState::BOOTSTRAPPING:
            tick_bootstrapping();
            break;

        case ClientState::MQTT_LINKING:
            tick_mqtt_connecting();
            break;

        case ClientState::MQTT_LINKED:
            set_state(ClientState::SUBSCRIBING);
            break;

        case ClientState::SUBSCRIBING:
            tick_subscribing();
            break;

        case ClientState::HELLO_SENT:
            tick_hello();
            break;

        case ClientState::READY:
            tick_ready();
            break;

        case ClientState::RECONNECTING:
            tick_reconnecting();
            break;

        case ClientState::ERROR_STATE:
            break;
    }
}

/* ── State Machine Tick Handlers ────────────────────────────────────── */

void Client::tick_provisioning() {
    provisioning_.loop();
    if (provisioning_.isComplete()) {
        /* Soft Reboot to pick up new NVS settings */
        Serial.println("[HXTP] Provisioning done. Restarting...");
        delay(1000);
        ESP.restart();
    }
}

void Client::tick_wifi_connecting() {
    if (WiFi.status() == WL_CONNECTED) {
        set_state(ClientState::WIFI_CONNECTED);
        return;
    }

    /* Timeout after 30 seconds */
    if (millis() - state_enter_ms_ > 30000) {
        if (error_cb_) error_cb_(Error::WIFI_CONNECT_FAILED, "WiFi timeout", error_ctx_);
        set_state(ClientState::RECONNECTING);
    }
}

void Client::tick_time_syncing() {
#ifdef ESP32
    /* Use ESP32 SNTP helper */
    if (platform::esp32_sync_time("pool.ntp.org", 100)) {
        set_state(ClientState::BOOTSTRAPPING);
        return;
    }
#else
    /* ESP8266: configTime was already set in begin() */
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    struct tm ti;
    localtime_r(&tv.tv_sec, &ti);
    if (ti.tm_year > (2020 - 1900)) {
        set_state(ClientState::BOOTSTRAPPING);
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
        set_state(ClientState::BOOTSTRAPPING);
    }
}

void Client::tick_bootstrapping() {
    /* Perform cloud discovery via signed HTTP request */
    BootstrapConfig bcfg = bootstrap_.perform();

    if (bcfg.success) {
        snprintf(mqtt_host_, sizeof(mqtt_host_), "%s", bcfg.mqtt_host);
        mqtt_port_ = bcfg.mqtt_port;
        
        /* Update config for later use */
        const_cast<Config*>(&config_)->heartbeat_interval_seconds = bcfg.heartbeat_interval_seconds;

        mqtt_client_.setServer(mqtt_host_, mqtt_port_);
        set_state(ClientState::MQTT_LINKING);
        
        Serial.print("[HXTP] Bootstrap success. Broker: ");
        Serial.println(mqtt_host_);
    } else {
        if (error_cb_) error_cb_(Error::BOOTSTRAP_FAILED, "Secure bootstrap failed", error_ctx_);
        set_state(ClientState::RECONNECTING);
    }
}

void Client::tick_mqtt_connecting() {
    if (mqtt_client_.connected()) {
        set_state(ClientState::MQTT_LINKED);
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
        set_state(ClientState::MQTT_LINKED);
    } else {
        if (error_cb_) {
            error_cb_(Error::BROKER_CONNECT_FAILED, "MQTT connect failed", error_ctx_);
        }
        set_state(ClientState::RECONNECTING);
    }
}

void Client::tick_subscribing() {
    if (subscribe_topics()) {
        set_state(ClientState::HELLO_SENT);

        /* Send HELLO */
        size_t out_len = 0;
        Error err = core_.build_hello(tx_buf_, sizeof(tx_buf_), &out_len);
        if (err == Error::OK && out_len > 0) {
            char topic[128];
            core_.build_topic(Channel::HELLO, topic, sizeof(topic));
            mqtt_client_.publish(topic, tx_buf_, out_len);
        }
    } else {
        if (error_cb_) error_cb_(Error::BROKER_SUBSCRIBE_FAILED, "Subscribe failed", error_ctx_);
        set_state(ClientState::RECONNECTING);
    }
}

void Client::tick_hello() {
    mqtt_client_.loop();

    /* Transition to READY after a short delay to allow server to process HELLO.
     * Real production would wait for a HELLO_ACK, but protocol spec allows
     * immediate transition for embedded devices. */
    if (millis() - state_enter_ms_ > 2000) {
        set_state(ClientState::READY);
    }
}

void Client::tick_ready() {
    /* MQTT keepalive */
    if (!mqtt_client_.loop()) {
        /* Connection lost */
        set_state(ClientState::RECONNECTING);
        return;
    }

    /* Check WiFi */
    if (WiFi.status() != WL_CONNECTED) {
        set_state(ClientState::RECONNECTING);
        return;
    }

    /* Heartbeat timer */
    uint32_t now = millis();
    uint32_t hb_interval = config_.heartbeat_interval_seconds * 1000;
    if (hb_interval == 0) hb_interval = HeartbeatIntervalSec * 1000;

    if (now - last_heartbeat_ms_ >= hb_interval) {
        send_heartbeat();
        last_heartbeat_ms_ = now;
    }
}

void Client::tick_reconnecting() {
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
        set_state(ClientState::WIFI_CONNECTING);
    } else {
        set_state(ClientState::MQTT_LINKING);
    }
}

/* ── Heartbeat ──────────────────────────────────────────────────────── */

void Client::send_heartbeat() {
    size_t out_len = 0;
    Error err = core_.build_heartbeat(tx_buf_, sizeof(tx_buf_), &out_len);
    if (err != Error::OK || out_len == 0) return;

    char topic[128];
    core_.build_topic(Channel::HEARTBEAT, topic, sizeof(topic));
    mqtt_client_.publish(topic, tx_buf_, out_len);
}

/* ── MQTT Subscriptions ─────────────────────────────────────────────── */

bool Client::subscribe_topics() {
    char topic[128];

    /* Subscribe to command channel */
    core_.build_topic(Channel::CMD, topic, sizeof(topic));
    if (!mqtt_client_.subscribe(topic, MqttQos)) return false;

    /* Subscribe to OTA channel */
    core_.build_topic(Channel::OTA, topic, sizeof(topic));
    if (!mqtt_client_.subscribe(topic, MqttQos)) return false;

    return true;
}

/* ── MQTT Message Handling ──────────────────────────────────────────── */

// cppcheck-suppress constParameterCallback
void Client::mqtt_callback_static(char* topic, uint8_t* payload, unsigned int length) {
    if (s_instance_) {
        s_instance_->mqtt_on_message(topic, payload, length);
    }
}

void Client::mqtt_on_message(const char* topic, const uint8_t* payload, unsigned int length) {
    if (!payload || length == 0) return;

    /* Process through core engine */
    size_t ack_len = 0;
    Error err = core_.process_inbound(
        topic,
        payload, static_cast<size_t>(length),
        ack_buf_, sizeof(ack_buf_), &ack_len
    );

    /* If ACK was generated, publish it */
    if (ack_len > 0) {
        char ack_topic[128];
        core_.build_topic(Channel::CMD_ACK, ack_topic, sizeof(ack_topic));
        mqtt_client_.publish(ack_topic, ack_buf_, ack_len);
    }

    /* Report errors */
    if (err != Error::OK && error_cb_) {
        error_cb_(err, error_str(err), error_ctx_);
    }
}

/* ── Publish APIs ───────────────────────────────────────────────────── */

Error Client::publishState(const char* state_json, uint32_t state_len) {
    if (!isConnected()) return Error::PROTOCOL_NOT_READY;

    size_t out_len = 0;
    Error err = core_.build_state(state_json, state_len, tx_buf_, sizeof(tx_buf_), &out_len);
    if (err != Error::OK) return err;

    char topic[128];
    core_.build_topic(Channel::STATE, topic, sizeof(topic));

    if (!mqtt_client_.publish(topic, tx_buf_, out_len)) {
        return Error::BROKER_PUBLISH_FAILED;
    }

    return Error::OK;
}

Error Client::publishTelemetry(const char* json, uint32_t json_len) {
    if (!isConnected()) return Error::PROTOCOL_NOT_READY;

    size_t out_len = 0;
    Error err = core_.build_telemetry(json, json_len, tx_buf_, sizeof(tx_buf_), &out_len);
    if (err != Error::OK) return err;

    char topic[128];
    core_.build_topic(Channel::TELEMETRY, topic, sizeof(topic));

    if (!mqtt_client_.publish(topic, tx_buf_, out_len)) {
        return Error::BROKER_PUBLISH_FAILED;
    }

    return Error::OK;
}

/* ── Disconnect ─────────────────────────────────────────────────────── */

void Client::disconnect() {
    mqtt_client_.disconnect();
    WiFi.disconnect();
    set_state(ClientState::IDLE);
}

/* ── State Helpers ──────────────────────────────────────────────────── */

bool Client::isWiFiConnected() const {
    return WiFi.status() == WL_CONNECTED;
}

bool Client::isMqttConnected() {
    return mqtt_client_.connected();
}

const char* Client::stateStr() const {
    switch (state_) {
        case ClientState::IDLE:             return "IDLE";
        case ClientState::WIFI_CONNECTING:  return "WIFI_CONNECTING";
        case ClientState::WIFI_CONNECTED:   return "WIFI_CONNECTED";
        case ClientState::TIME_SYNCING:     return "TIME_SYNCING";
        case ClientState::MQTT_LINKING:  return "MQTT_CONNECTING";
        case ClientState::MQTT_LINKED:   return "MQTT_CONNECTED";
        case ClientState::SUBSCRIBING:      return "SUBSCRIBING";
        case ClientState::HELLO_SENT:       return "HELLO_SENT";
        case ClientState::READY:            return "READY";
        case ClientState::RECONNECTING:     return "RECONNECTING";
        case ClientState::ERROR_STATE:      return "ERROR";
        default:                                return "UNKNOWN";
    }
}

void Client::set_state(ClientState new_state) {
    if (new_state == state_) return;

    ClientState old = state_;
    state_ = new_state;
    state_enter_ms_ = millis();

    if (state_change_cb_) {
        state_change_cb_(old, new_state, state_change_ctx_);
    }
}

void Client::onStateChange(StateCallback cb, void* ctx) {
    state_change_cb_ = cb;
    state_change_ctx_ = ctx;
}

void Client::onError(ErrorCallback cb, void* ctx) {
    error_cb_ = cb;
    error_ctx_ = ctx;
}

} /* namespace hxtp */
