# hxtp-micro

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)](https://github.com/hestialabs/hxtp-micro)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-ESP32%20%7C%20ESP8266-orange.svg)](https://espressif.com/)

HxTP-micro is a high-performance embedded SDK implementing the HxTP/3.1 protocol for ESP32 and ESP8266 devices. The SDK is designed for deterministic execution, secure message validation, and low-memory embedded environments.

## Features

* Zero dynamic allocation in the hot path
* Full HxTP/3.1 7-step validation pipeline
* Bit-perfect HMAC-SHA256 signature parity with Go, JavaScript, and Python SDKs
* Native support for ESP32 and ESP8266 platforms
* Capability-based action registry
* Dual-key rotation support
* Deterministic validation and execution flow
* Optimized for constrained embedded systems

---

# Installation

## PlatformIO

Add the following configuration to your `platformio.ini` file:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
    hxtp-micro@^1.0.3
    knolleary/PubSubClient@^2.8
    bblanchon/ArduinoJson@^7.0.0

build_flags =
    -std=gnu++17
    -DHXTP_RELEASE=1
```

---

# Quick Start

## Basic Example

```cpp
#include <Hxtp.h>

hxtp::Client* client = nullptr;

hxtp::CapabilityResult toggle_led(
    const char* params,
    uint32_t len,
    void* ctx
) {
    // Device logic

    return { true, 0, "" };
}

void setup() {
    Serial.begin(115200);

    hxtp::Config config;

    config.wifi_ssid     = "Your-SSID";
    config.wifi_password = "Your-Password";

    config.api_base_url  = "https://api.hestialabs.in/v1";
    config.device_id     = "your-32-char-hex-id";
    config.tenant_id     = "your-uuid-tenant-id";
    config.device_secret = "your-64-char-hex-secret";

    client = new hxtp::Client(config);

    client->registerCapability(
        1,
        "toggle_led",
        toggle_led
    );

    client->begin();
    client->connect();
}

void loop() {
    if (client) {
        client->loop();
    }
}
```

---

# HxTP/3.1 Validation Pipeline

Every inbound message is validated through a deterministic 7-step security pipeline:

1. Version validation
2. Timestamp freshness validation
3. Payload size enforcement
4. Nonce uniqueness verification
5. SHA-256 payload hash validation
6. Sequence monotonicity enforcement
7. HMAC-SHA256 signature verification

This pipeline provides replay protection, integrity verification, deterministic execution ordering, and fail-closed message handling.

---

# Architecture Goals

HxTP-micro is designed around the following principles:

* Deterministic execution
* Fail-closed validation
* Embedded-first memory efficiency
* Cross-SDK cryptographic parity
* Minimal runtime overhead
* Secure device-to-cloud communication

---

# Platform Support

| Platform | Status    |
| -------- | --------- |
| ESP32    | Supported |
| ESP32-S3 | Supported |
| ESP32-C3 | Supported |
| ESP8266  | Supported |

---

# License

This project is licensed under the MIT License. See `LICENSE.txt` for details.

Copyright © 2026 Hestia Labs
