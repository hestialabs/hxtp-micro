# 🛡️ HXTP Embedded SDK

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)](https://github.com/hestialabs/hxtp-micro)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-ESP32%20%7C%20ESP8266-orange.svg)](https://espressif.com/)
[![Framework](https://img.shields.io/badge/framework-Arduino%20%7C%20PlatformIO-0288d1.svg)](https://platformio.org/)

**HxTP/3.0** protocol implementation for high-performance, secure IoT devices. Optimized for ESP32 and ESP8266, featuring zero dynamic allocation in the hot path and strict security enforcement.

---

## 🚀 Key Features

- **⚡ Zero Dynamic Allocation**: High-performance core designed for memory-constrained devices.
- **🔐 Enterprise Security**: Mandatory HMAC-SHA256 signatures and strict TLS verification.
- **📦 Multi-Platform**: Native support for ESP32 (S3, C3, DevKit) and ESP8266 (NodeMCU, Wemos).
- **🔄 Zero-Config Onboarding**: Automated provisioning via SoftAP and secure discovery.
- **🛡️ Anti-Replay**: Integrated nonce cache and monotonic sequence verification.
- **🔌 Capability Registry**: Simplified handler registration for device actions.

---

## 📋 Supported Boards

| Board | Platform | Crypto Backend | RAM | Flash |
| :--- | :--- | :--- | :--- | :--- |
| **ESP32-S3 DevKit** | `espressif32` | mbedTLS | 13.8% | 29.6% |
| **ESP32 DevKit v1** | `espressif32` | mbedTLS | 13.9% | 51.7% |
| **NodeMCU v2** | `espressif8266` | BearSSL | 39.5% | 39.6% |
| **Wemos D1 Mini** | `espressif8266` | BearSSL | 39.5% | 39.6% |

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
    hxtp-micro
    knolleary/PubSubClient@^2.8
build_flags =
    -std=gnu++17
    -DHXTP_RELEASE=1
```

### 2. Implementation
Initialize the client and register your capabilities in `main.cpp`:

```cpp
#include <Hxtp.h>

hxtp::Client client;

void setup() {
    Config config;
    config.device_type = "smart-sensor";
    config.firmware_version = "1.1.0";
    config.verify_server = true; 

    client.begin(config);
    
    // Register a capability (Action ID, Name, Handler)
    client.registerCapability(1, "toggle_led", [](const char* params, uint32_t len, void* ctx) {
        // Handle LED toggle logic here
        return CapabilityResult{true, 0, ""};
    });
    
    client.connect(); // Auto-provisioning if credentials missing
}

void loop() {
    client.loop(); // Internal state machine (Provisioning -> MQTT)
}
```

---

## 🔄 The Onboarding Lifecycle

1.  **📡 Provisioning (SoftAP)**: If unconfigured, the device hosts `HXTP-XXXX`. Use the HestiaLabs portal to claim.
2.  **🔑 Secure Bootstrap**: Performs HMAC-signed discovery to locate MQTT brokers and cloud parameters.
3.  **🟢 Ready**: Device is online and ready for zero-latency commands.

---

## 🔐 Protocol: MCSS v3.0

The SDK implements the **Modern Cloud Security Specification (MCSS) v3.0**. All messages carry a mandatory HMAC-SHA256 signature computed over a frozen canonical string:

`version|device_id|client_id|message_id|request_id|sequence_number|timestamp|nonce|message_type|payload_hash`

- **Immutable Chain**: Guaranteed monotonic sequence numbers per device session.
- **Payload Integrity**: SHA-256 hashing of all JSON bodies before signing.
- **Replay Protection**: Per-session UUID v4 `client_id` coupled with a 600s nonce window.

---

## 🛠️ Memory Footprint (Production Build)

| Component | Flash | RAM (Static) | RAM (Stack Peak) |
| :--- | :--- | :--- | :--- |
| **Core & Frames** | ~3 KB | 0 | 0 |
| **Crypto (mbedTLS/BearSSL)** | ~4-8 KB | 0 | ~1-2 KB |
| **Validation Pipeline** | ~3 KB | ~5 KB* | ~1 KB |
| **HXTP Engine** | ~7 KB | ~9.5 KB† | ~1 KB |
| **Total (ESP32)** | **~21 KB** | **~14.5 KB** | **~4 KB** |
| **Total (ESP8266)** | **~17 KB** | **~11 KB** | **~3 KB** |

> \* *Includes Nonce cache (64 entries).*
> † *Includes TX/RX buffers and state tracking.*

---

## ⚖️ Security Constraints

| Constraint | Enforcement Mechanism |
| :--- | :--- |
| **Mandatory Signatures** | All packets must carry valid HMAC-SHA256 |
| **Anti-Replay** | 600s sliding window Nonce cache + Monotonic counters |
| **No Heap in Loop** | Deterministic memory usage, all buffers pre-allocated |
| **Fail-Closed** | Any validation error triggers immediate packet rejection |
| **TLS Strict Mode** | `setInsecure()` is compilation-blocked in RELEASE builds |
| **OTA Integrity** | Cloud-enforced Ed25519 signatures |

---

## 📂 Project Structure

```text
src/
├── Hxtp.h               # Umbrella header
├── Config.h             # Tunables & Flags
├── Types.h              # Protocol constants
├── Crypto.h             # Crypto abstraction
├── Frame.h / .cpp       # Packet serialization
├── Validation.h / .cpp  # Security pipeline
├── Capability.h / .cpp  # Handler registry
└── HxtpClient.h / .cpp  # High-level API
```

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE.txt](LICENSE.txt) for details.

Copyright © 2026 **Hestia Labs**
