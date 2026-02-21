/*
 * HXTP Embedded SDK v1.0
 * Arduino Client Wrapper — Header
 *
 * High-level API for Arduino sketches:
 *   HXTPClient client(config);
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
    #include "PlatformESP32.h"
    #include "StorageNVS.h"
#elif defined(ESP8266)
    #include <ESP8266WiFi.h>
    #include <WiFiClientSecure.h>
    #include "PlatformESP8266.h"
#endif

namespace hxtp {

/* ── Connection State Machine ───────────────────────────────────────── */

enum class HxtpClientState : uint8_t {
    IDLE            = 0,    /* Not started */
    WIFI_CONNECTING = 1,    /* Connecting to WiFi */
    WIFI_CONNECTED  = 2,    /* WiFi up, not yet MQTT */
    TIME_SYNCING    = 3,    /* Waiting for NTP */
    MQTT_LINKING    = 4,    /* Connecting to MQTT broker */
    MQTT_LINKED     = 5,    /* MQTT up, subscribing */
    SUBSCRIBING     = 6,    /* Subscribing to topics */
    HELLO_SENT      = 7,    /* HELLO handshake sent */
    READY           = 8,    /* Fully operational */
    RECONNECTING    = 9,    /* Lost connection, retrying */
    ERROR_STATE     = 10,   /* Fatal error */
};

/* ── Callback Types ─────────────────────────────────────────────────── */

typedef void (*HxtpStateChangeCallback)(HxtpClientState old_state, HxtpClientState new_state, void* ctx);
typedef void (*HxtpErrorCallback)(HxtpError err, const char* msg, void* ctx);

/* ── HXTPClient ─────────────────────────────────────────────────────── */

class HXTPClient {
public:
    /**
     * Construct with configuration.
     */
    explicit HXTPClient(const HXTPConfig& config);

    /**
     * Initialize all subsystems.
     * Call once in Arduino setup().
     * @return HxtpError::OK or initialization error
     */
    HxtpError begin();

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
     * @return            HxtpError::OK or error
     */
    HxtpError publishState(const char* state_json, uint32_t state_len);

    /**
     * Publish telemetry data.
     */
    HxtpError publishTelemetry(const char* json, uint32_t json_len);

    /* ── State & Status ──────────────────────────────── */

    HxtpClientState state() const { return state_; }
    bool isConnected() const { return state_ == HxtpClientState::READY; }
    bool isWiFiConnected() const;
    bool isMqttConnected();
    const char* stateStr() const;

    /* ── Callbacks ────────────────────────────────────── */

    void onStateChange(HxtpStateChangeCallback cb, void* ctx = nullptr);
    void onError(HxtpErrorCallback cb, void* ctx = nullptr);

    /* ── Accessors ────────────────────────────────────── */

    HxtpCore& core() { return core_; }
    const char* deviceId() const { return core_.device_id(); }
    const char* tenantId() const { return core_.tenant_id(); }

private:
    /* ── State Machine Handlers ────────────────────────── */
    void tick_wifi_connecting();
    void tick_time_syncing();
    void tick_mqtt_connecting();
    void tick_subscribing();
    void tick_hello();
    void tick_ready();
    void tick_reconnecting();

    /* ── MQTT Message Handler ──────────────────────────── */
    static void mqtt_callback_static(char* topic, uint8_t* payload, unsigned int length);
    void mqtt_on_message(char* topic, uint8_t* payload, unsigned int length);

    /* ── Heartbeat ────────────────────────────────────── */
    void send_heartbeat();

    /* ── Topic Subscriptions ──────────────────────────── */
    bool subscribe_topics();

    /* ── State Transition ─────────────────────────────── */
    void set_state(HxtpClientState new_state);

    /* ── Config ──────────────────────────────────────── */
    HXTPConfig  config_;

    /* ── Core Engine ─────────────────────────────────── */
    HxtpCore    core_;

    /* ── Platform Adapters ───────────────────────────── */
    HxtpStorageAdapter   storage_adapter_;
    HxtpPlatformCrypto   platform_crypto_;

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
    HxtpClientState      state_;

    /* ── Timers ──────────────────────────────────────── */
    uint32_t  last_heartbeat_ms_;
    uint32_t  last_reconnect_ms_;
    uint32_t  reconnect_delay_ms_;
    uint32_t  state_enter_ms_;

    /* ── Callbacks ───────────────────────────────────── */
    HxtpStateChangeCallback  state_change_cb_;
    void*                    state_change_ctx_;
    HxtpErrorCallback        error_cb_;
    void*                    error_ctx_;

    /* ── Frame Buffers (stack, not heap) ─────────────── */
    /* Outbound buffer shared across sends */
    uint8_t  tx_buf_[HXTP_FRAME_BUF_DEFAULT];
    /* Inbound ACK buffer — constrained on ESP8266 */
#if defined(HXTP_CONSTRAINED)
    uint8_t  ack_buf_[512];
#else
    uint8_t  ack_buf_[1024];
#endif

    /* ── Singleton for static callback routing ───────── */
    static HXTPClient* s_instance_;
};

} /* namespace hxtp */

#endif /* HXTP_CLIENT_H */
