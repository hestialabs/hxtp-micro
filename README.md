# hxtp-micro

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)](https://github.com/hestialabs/hxtp-micro)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-ESP32%20%7C%20ESP8266-orange.svg)](https://espressif.com/)

**HxTP-micro**is a high-performance, secure IoT SDK implementing the **HxTP/3.1**protocol.It features zero dynamic allocation in the hot path, strict 7-step Ed25519 validation, and bit-perfect signature parity with Hestia Labs' backend.

---

## Key Features

- **Zero Dynamic Allocation**: High-performance core designed for memory-constrained environments.
- **HxTP/3.1 Ed25519 Pipeline**: Full implementation of the hardened 7-step security pipeline.
- **Identity-as-Root**: Device generates its own Ed25519 private key. The private key NEVER leaves the device hardware.
- **Asymmetric Trust**: Every message is signed with Ed25519. No shared secrets or permanent credentials stored in the cloud.
- **Zero-Config WiFi**: Automatic SoftAP provisioning — no WiFi credentials in your code.
- **Multi-Platform**: Native support for ESP32 (S3, C3, DevKit) and ESP8266.
- **Capability Registry**: Simplified handler registration for device actions.
- **Session Isolation**: MQTT transport uses short-lived tokens, isolated from protocol-level identity.

---

## ⏱ Quick Start (PlatformIO)

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

The SDK handles WiFi provisioning, identity generation, enrollment, bootstrap, and session management automatically. Your firmware only needs two configuration fields:

```cpp
#include <Hxtp.h>

hxtp::Client* client = nullptr;

hxtp::CapabilityResult toggle_led(
  const char* params,
  uint32_t len,
  void* ctx
) {
  // Your device logic (e.g. digitalWrite)
  return { true, 0, "" };
}

void setup() {
  Serial.begin(115200);

  hxtp::Config config;
  config.api_base_url = "https://api.hestialabs.in/v1";
  config.device_uuid = "permanent-hardware-uuid";

  client = new hxtp::Client(config);

  // Register capabilities
  client->registerCapability(1, "toggle_led", toggle_led);

  // Start — handles everything internally
  client->begin();
  client->connect();
}

void loop() {
  if (client) {
    client->loop();
  }
}
```

That's it. No WiFi passwords, no API keys, no cloud keys in your code.

---

## WiFi Provisioning

WiFi credentials are **never hardcoded**. The SDK manages onboarding automatically:

1. **First boot**: No stored credentials → SDK starts a **SoftAP**(`HXTP-XXXX`).
2. **User connects**to the AP and submits WiFi credentials via the captive portal.
3. **Credentials persist**in NVS/EEPROM — subsequent boots connect automatically.
4. **Reconnection**is handled internally with exponential backoff.

---

## Security Architecture

### Trust Model

| Component | Source | Purpose |
|---|---|---|
| **Device Private Key**| Generated on-device (Ed25519) | Signs all protocol traffic |
| **Cloud Root Public Key**| Compiled into firmware | Verifies server messages |
| **MQTT Session Token**| Issued by cloud at bootstrap | Transport-only, short-lived |
| **Enrollment Token**| Acquired via SoftAP/dashboard claim | One-time bootstrap credential |

None of these appear in the developer's `Config` struct. They are all internally managed.

### 7-Step Validation Pipeline

Every inbound message passes through a hardened pipeline:

1. **Version Check**— Rejects protocol version mismatch (must be HxTP/3.1).
2. **Timestamp Freshness**— Enforces strict time windows (±30s).
3. **Payload Size**— Prevents buffer overflow via size enforcement.
4. **Nonce Uniqueness**— Ring-buffered cache protects against replay.
5. **Payload Hash**— SHA-256 integrity verification.
6. **Sequence Monotonicity**— Protects against out-of-order execution.
7. **Ed25519 Signature**— Cryptographic verification using the Cloud Root Key.

---

## Advanced Configuration

For production deployments, you may optionally configure:

```cpp
hxtp::Config config;
config.api_base_url     = "https://api.hestialabs.in/v1"; // Required
config.device_uuid      = "hardware-uuid";         // Required
config.ca_cert        = pemCertString;          // Optional: custom CA
config.verify_server     = true;               // Default: true
config.frame_buf_size    = 4096;               // Default: 4096
config.max_reconnect_delay_ms = 60000;              // Default: 60000
```

To override the compiled-in Cloud Root Key (e.g. for staging environments), use a build flag:

```ini
build_flags =
  -DHXTP_CLOUD_ROOT_KEY=\"your_staging_key_hex\"
```

---

## Memory Footprint

| Target | RAM | Flash |
|---|---|---|
| ESP32-S3 (8 MB) | 13.9% (45 KB / 320 KB) | 26.6% (888 KB / 3.3 MB) |
| ESP32 (4 MB) | 13.9% (45 KB / 320 KB) | 51.7% (1016 KB / 1.9 MB) |
| ESP8266 (4 MB) | 39.5% (32 KB / 80 KB) | 39.6% (414 KB / 1.0 MB) |

---

## License

This project is licensed under the MIT License. See `LICENSE.txt` for details.

Copyright © 2026 Hestia Labs
