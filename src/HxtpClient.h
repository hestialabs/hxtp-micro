/*
 * HXTP Embedded SDK v1.0
 * Arduino Client Wrapper — Header
 *
 * High-level API for Arduino sketches:
 *   Client client(config);
 *   client.begin();
 *   client.registerCapability(1, "set_pin", handler);
 *   client.connect();
 *   client.loop();    // call in Arduino loop()
 *
 * Manages: WiFi, TLS, MQTT, heartbeats, reconnection, and protocol engine.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_CLIENT_H
#define HXTP_CLIENT_H

#include "Config.h"
#include "Types.h"
#include "Errors.h"
#include "Core.h"

#include <Arduino.h>
#include <Client.h>

/* PubSubClient for MQTT (standard Arduino library) */
#include <PubSubClient.h>

/* TLS client selection */
#ifdef ESP32
    #include <WiFi.h>
    #include <WiFiClientSecure.h>
    #include "Esp32.h"
    #include "Nvs.h"
#elif defined(ESP8266)
    #include <ESP8266WiFi.h>
    #include <WiFiClientSecure.h>
    #include "Esp8266.h"
#endif

#ifdef ESP32
#include <HTTPClient.h>
#elif defined(ESP8266)
#include <ESP8266HTTPClient.h>
#endif

#include "Provisioning.h"
#include "Bootstrap.h"

namespace hxtp {

/* ── Connection State Machine ───────────────────────────────────────── */

enum class ClientState : uint8_t {
    IDLE            = 0,    /* Not started */
    PROVISIONING    = 1,    /* AP + WebServer setup */
    WIFI_CONNECTING = 2,    /* Connecting to WiFi */
    WIFI_CONNECTED  = 3,    /* WiFi up, not yet MQTT */
    TIME_SYNCING    = 4,    /* Waiting for NTP */
    BOOTSTRAPPING   = 5,    /* Fetching config via HTTP */
    MQTT_LINKING    = 6,    /* Connecting to MQTT broker */
    MQTT_LINKED     = 7,    /* MQTT up, subscribing */
    SUBSCRIBING     = 8,    /* Subscribing to topics */
    HELLO_SENT      = 9,    /* HELLO handshake sent */
    READY           = 10,   /* Fully operational */
    RECONNECTING    = 11,   /* Lost connection, retrying */
    ERROR_STATE     = 12,   /* Fatal error */
};

/* ── Callback Types ─────────────────────────────────────────────────── */

typedef void (*StateCallback)(ClientState old_state, ClientState new_state, void* ctx);
typedef void (*ErrorCallback)(Error err, const char* msg, void* ctx);

/* ── Client ─────────────────────────────────────────────────────── */

class Client {
public:
    /**
     * Construct with configuration.
     */
    explicit Client(const Config& config);

    /**
     * Initialize all subsystems.
     * Call once in Arduino setup().
     * @return Error::OK or initialization error
     */
    Error begin();

    /**
     * Register a device capability.
     * Must be called before connect().
     */
    bool registerCapability(uint16_t id, const char* action,
                            CapabilityHandler handler, void* user_ctx = nullptr);

    /**
     * Start the connection sequence (WiFi → TLS → MQTT → HELLO).
     * Non-blocking — progress is made in loop().
     */
    void connect();

    /**
     * Main loop tick. Call in Arduino loop().
     * Handles: MQTT keepalive, heartbeats, reconnection, inbound messages.
     *
     * MUST be called frequently (< 100ms between calls).
     * Does NOT allocate heap.
     */
    void loop();

    /**
     * Disconnect cleanly.
     */
    void disconnect();

    /**
     * Publish a state report.
     * @param state_json  JSON object string (e.g., "{\"pin\":1}")
     * @param state_len   Length of JSON string
     * @return            Error::OK or error
     */
    Error publishState(const char* state_json, uint32_t state_len);

    /**
     * Publish telemetry data.
     */
    Error publishTelemetry(const char* json, uint32_t json_len);

    /* ── State & Status ──────────────────────────────── */

    ClientState state() const { return state_; }
    bool isConnected() const { return state_ == ClientState::READY; }
    bool isWiFiConnected() const;
    bool isMqttConnected();
    const char* stateStr() const;

    /* ── Callbacks ────────────────────────────────────── */

    void onStateChange(StateCallback cb, void* ctx = nullptr);
    void onError(ErrorCallback cb, void* ctx = nullptr);

    /* ── Accessors ────────────────────────────────────── */

    Core& core() { return core_; }
    const char* deviceId() const { return core_.device_id(); }
    const char* tenantId() const { return core_.tenant_id(); }

private:
    /* ── State Machine Handlers ────────────────────────── */
    void tick_provisioning();
    void tick_wifi_connecting();
    void tick_time_syncing();
    void tick_bootstrapping();
    void tick_mqtt_connecting();
    void tick_subscribing();
    void tick_hello();
    void tick_ready();
    void tick_reconnecting();

    /* ── MQTT Message Handler ──────────────────────────── */
    static void mqtt_callback_static(char* topic, uint8_t* payload, unsigned int length);
    void mqtt_on_message(const char* topic, const uint8_t* payload, unsigned int length);

    /* ── Heartbeat ────────────────────────────────────── */
    void send_heartbeat();

    /* ── Topic Subscriptions ──────────────────────────── */
    bool subscribe_topics();

    /* ── State Transition ─────────────────────────────── */
    void set_state(ClientState new_state);

    /* ── Config ──────────────────────────────────────── */
    Config  config_;

    /* ── Fetched Bootstrapped Config ─────────────────── */
    char        mqtt_host_[64];
    uint16_t    mqtt_port_;
    
    /* ── Core Engine ─────────────────────────────────── */
    Core    core_;

    /* ── Platform Adapters ───────────────────────────── */
    StorageAdapter   storage_adapter_;
    PlatformCrypto   platform_crypto_;

    /* ── Provisioning & Bootstrap ────────────────────── */
    Provisioning         provisioning_;
    Bootstrap            bootstrap_;

    /* ── Network ─────────────────────────────────────── */
#ifdef ESP8266
    BearSSL::WiFiClientSecure tls_client_;
#else
    WiFiClientSecure     tls_client_;
#endif
    PubSubClient         mqtt_client_;

#ifdef ESP8266
    /* BearSSL requires X509List to stay alive for the TLS session */
    BearSSL::X509List*   x509_ca_;
#endif

    /* ── State Machine ───────────────────────────────── */
    ClientState      state_;

    /* ── Timers ──────────────────────────────────────── */
    uint32_t  last_heartbeat_ms_;
    uint32_t  last_reconnect_ms_;
    uint32_t  reconnect_delay_ms_;
    uint32_t  state_enter_ms_;

    /* ── Callbacks ───────────────────────────────────── */
    StateCallback  state_change_cb_;
    void*                    state_change_ctx_;
    ErrorCallback        error_cb_;
    void*                    error_ctx_;

    /* ── Frame Buffers (stack, not heap) ─────────────── */
    /* Outbound buffer shared across sends */
    uint8_t  tx_buf_[FrameBufDefault];
    /* Inbound ACK buffer — constrained on ESP8266 */
#if defined(HXTP_CONSTRAINED)
    uint8_t  ack_buf_[512];
#else
    uint8_t  ack_buf_[1024];
#endif

    /* ── Singleton for static callback routing ───────── */
    static Client* s_instance_;
};

} /* namespace hxtp */

#endif /* HXTP_CLIENT_H */
