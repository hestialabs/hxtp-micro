# 🛡️ HXTP Embedded SDK

[![Version](https://img.shields.io/badge/version-1.0.7-blue.svg)](https://github.com/hestialabs/hxtp-micro)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-ESP32%20%7C%20ESP8266-orange.svg)](https://espressif.com/)

**HxTP/3.1** protocol implementation for high-performance, secure IoT devices. Optimized for ESP32 and ESP8266, featuring zero dynamic allocation in the hot path and strict security enforcement.

---

## 🚀 Key Features

- **⚡ Zero Dynamic Allocation**: High-performance core designed for memory-constrained devices.
- **🔐 HxTP/3.1 Core**: Pipe-separated framing with mandatory backslash escaping.
- **🛡️ Bit-Perfect Parity**: Exact signature parity with Go, JS, and Python SDKs.
- **📦 Multi-Platform**: Native support for ESP32 (S3, C3, DevKit) and ESP8266.
- **🔌 Capability Registry**: Simplified handler registration for device actions.

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
    -DHXTP_VERSION=31
```

### 2. Implementation
Initialize the client and register your capabilities:

```cpp
#include <Hxtp.h>

hxtp::Client* client = nullptr;

void setup() {
    hxtp::Config config;
    config.device_id = "your-device-uuid";
    config.secret = "your-64-char-hex-secret";
    config.version = hxtp::ProtocolVersion::V31; 

    client = new hxtp::Client(config);
    client->begin();
    
    // Register a capability (Action ID, Name, Handler)
    client->registerCapability(1, "set_led", [](const char* params, uint32_t len, void* ctx) {
        // Handle LED logic
        return CapabilityResult{true, 0, ""};
    });
}

void loop() {
    if (client) client->loop(); // Handles signing and validation
}
```

---

## 🔐 Protocol Alignment: HxTP/3.1

The SDK implements the **HxTP/3.1** specification with strict adherence to deterministic framing:

`version|message_id|request_id|device_id|tenant_id|client_id|sequence|timestamp|action|params_hash`

- **Escaping**: Mandatory backslash escaping for `|`, `\`, `\n`, and `\r`.
- **Monotonic Sequence**: Hardened sequence tracking to prevent out-of-order execution.
- **Fail-Closed**: Any validation error (HMAC, Timestamp, Nonce) triggers immediate rejection.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE.txt](LICENSE.txt) for details.

Copyright © 2026 **Hestia Labs**
