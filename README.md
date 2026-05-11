# hxtp-micro

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)](https://github.com/hestialabs/hxtp-micro)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-ESP32%20%7C%20ESP8266-orange.svg)](https://espressif.com/)

**HxTP-micro** is a high-performance, secure IoT SDK implementing the **HxTP/3.1** protocol. Optimized for ESP32 and ESP8266, it features zero dynamic allocation in the hot path, strict 7-step Ed25519 validation, and bit-perfect signature parity with Hestia Labs' backend.

---

## 🚀 Key Features

- **⚡ Zero Dynamic Allocation**: High-performance core designed for memory-constrained environments.
- **🔐 HxTP/3.1 Ed25519 Pipeline**: Full implementation of the hardened 7-step security pipeline.
- **🆔 Identity-as-Root**: Device generates its own Ed25519 private key. The private key NEVER leaves the device hardware.
- **🛡️ Public-Key Trust**: Every message is signed with Ed25519. No more shared secrets or permanent credentials.
- **📦 Multi-Platform**: Native support for ESP32 (S3, C3, DevKit) and ESP8266.
- **🔌 Capability Registry**: Simplified handler registration for device actions.
- **🔄 Session Isolation**: MQTT transport uses short-lived tokens, isolated from protocol-level identity.

---

## ⏱️ Quick Start (PlatformIO)

### 1. Add Dependencies
Add the following to your `platformio.ini`:

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

### 2. Basic Implementation
The SDK handles identity generation and claiming automatically.

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
    config.device_uuid   = "permanent-hardware-id";
    config.api_key       = "your-portal-api-key";

    client = new hxtp::Client(config);
    
    // 2. Register capabilities
    client->registerCapability(1, "toggle_led", toggle_led);

    // 3. Start the engine
    // Automatically handles Identity Generation -> Claim -> Session Issue
    client->begin();
    client->connect();
}

void loop() {
    if (client) {
        client->loop(); // Handles heartbeats, Ed25519 signing, and validation
    }
}
```

---

## 🔐 Security Pipeline: HxTP/3.1

The SDK implements a hardened **7-step validation pipeline** for every inbound message:

1.  **Version Check**: Rejects any protocol version mismatch (must be HxTP/3.1).
2.  **Timestamp Freshness**: Enforces strict time windows to prevent stale message execution.
3.  **Payload Size**: Prevents buffer overflow attacks via size enforcement.
4.  **Nonce Uniqueness**: Ring-buffered nonce cache protects against replay attacks.
5.  **Payload Hash**: Verifies data integrity using SHA-256.
6.  **Sequence Monotonicity**: Protects against out-of-order execution.
7.  **Signature Verification**: Ed25519 verification using the Cloud Root Key.

---

# License

This project is licensed under the MIT License. See `LICENSE.txt` for details.

Copyright © 2026 Hestia Labs
