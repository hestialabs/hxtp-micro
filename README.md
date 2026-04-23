# HXTP Embedded SDK v3.0

> HxTP/3.0 protocol implementation for ESP32 and ESP8266 IoT devices.\
> PlatformIO-native · Arduino framework · Zero dynamic allocation in hot path.

## Supported Boards

| Board           | Platform      | Crypto Backend | RAM Usage | Flash Usage |
| --------------- | ------------- | -------------- | --------- | ----------- |
| ESP32-S3 DevKit | espressif32   | mbedTLS        | 13.8%     | 29.6%       |
| ESP32 DevKit v1 | espressif32   | mbedTLS        | 13.9%     | 51.7%       |
| NodeMCU v2      | espressif8266 | BearSSL        | 39.5%     | 39.6%       |
| Wemos D1 Mini   | espressif8266 | BearSSL        | 39.5%     | 39.6%       |

## Quick Start (PlatformIO)

### 1. Add the library

In your `platformio.ini`:

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

### 2. Include the SDK

```cpp
#include <HXTP.h>
```

That's it — one header gives you everything: `Config`, `hxtp::Client`, `Error`,
all types.

### 3. Quick Start: Zero-Config Flow

Modern HxTP devices follow a **Zero-Config** flow. You don't need to hardcode
WiFi credentials or device secrets in your firmware.

```cpp
#include <Hxtp.h>

// Global Client instance
hxtp::Client client;

void setup() {
    Config config;
    config.device_type = "smart-sensor";
    config.firmware_version = "1.1.0";
    
    // Default to strict TLS verification
    config.verify_server = true; 

    // Initialize and start the engine
    client.begin(config);
    
    // Register a device capability (action)
    client.registerCapability(1, "toggle_led", [](const char* params, uint32_t len, void* ctx) {
        // ... handle LED toggle ...
        return CapabilityResult{true, 0, ""};
    });
    
    // Connect to HxTP Cloud (Auto-Provisioning if empty)
    client.connect();
}

void loop() {
    client.loop(); // Handles Provisioning, Bootstrap, and MQTT
}
```

### 4. The Onboarding Lifecycle

1. **Provisioning (SoftAP)**: If no credentials exist, the device starts Access
   Point `HXTP-XXXX`. Claim it via the HestiaLabs portal.
2. **Secure Bootstrap**: Performs an HMAC-signed discovery to find MQTT broker &
   cloud params.
3. **Ready**: Device is online and ready for zero-latency commands.

### 5. Capability Handler

```cpp
CapabilityResult my_handler(const char* params, uint32_t len, void* ctx) {
    CapabilityResult r{};
    int64_t val = 0;
    if (!hxtp::json_get_int64(params, len, "value", &val)) {
        r.success = false;
        r.error_code = static_cast<int16_t>(Error::INVALID_PARAMS);
        snprintf(r.error_msg, sizeof(r.error_msg), "Missing value");
        return r;
    }
    digitalWrite(LED_BUILTIN, val ? HIGH : LOW);
    r.success = true;
    return r;
}
```

## Protocol: MCSS v3.0

The SDK implements the **Modern Cloud Security Specification (MCSS) v3.0**. All
messages carry a mandatory HMAC-SHA256 signature computed over a frozen
pipe-delimited canonical string.

### Canonical String Format (10 Fields)

`version|device_id|client_id|message_id|request_id|sequence_number|timestamp|nonce|message_type|payload_hash`

- **client_id**: Generated as a UUID v4 per session to prevent cross-session
  replay.
- **sequence_number**: Guaranteed monotonic per device.
- **payload_hash**: SHA-256 hex of the raw JSON params/body.

## Memory Footprint

| Component           | Flash      | RAM (static) | RAM (stack)    |
| ------------------- | ---------- | ------------ | -------------- |
| Core types/errors   | ~2 KB      | 0            | 0              |
| Frame encoder       | ~1 KB      | 0            | 0              |
| Crypto (mbedTLS)    | ~8 KB      | 0            | ~2 KB/call     |
| Crypto (BearSSL)    | ~4 KB      | 0            | ~1 KB/call     |
| Validation pipeline | ~3 KB      | ~5 KB*       | ~1 KB/call     |
| JSON parser         | ~2 KB      | 0            | ~512 B/call    |
| Capability registry | ~1 KB      | ~1.5 KB†     | 0              |
| HXTPClient          | ~4 KB      | ~8 KB‡       | ~512 B         |
| **Total (ESP32)**   | **~21 KB** | **~14.5 KB** | **~4 KB peak** |
| **Total (ESP8266)** | **~17 KB** | **~11 KB**   | **~3 KB peak** |

\* Nonce cache: 64 entries × 60 bytes = ~3.8 KB (32 entries on ESP8266)\
† 32 capability slots × 48 bytes = ~1.5 KB (16 on ESP8266)\
‡ TX buffer (4 KB) + ACK buffer (1 KB / 512 B on ESP8266) + TLS + MQTT

## File Structure

```
SDK/C++/
├── platformio.ini               # Build targets: esp32s3, esp32, esp8266
├── lib/HXTP/
│   └── src/
│       ├── HXTP.h               # ← Umbrella header (public entry point)
│       ├── Config.h             # Stability contract, feature flags, tunables
│       ├── Types.h              # Protocol constants, types, HXTPConfig
│       ├── Errors.h             # Error codes (match server enum)
│       ├── HXTPCrypto.h         # Crypto interface (SHA-256, HMAC, AES-GCM)
│       ├── CryptoMbedTLS.cpp    # ESP32 crypto implementation (mbedTLS)
│       ├── CryptoBearSSL.cpp    # ESP8266 crypto implementation (BearSSL)
│       ├── Frame.h / Frame.cpp  # Binary frame encoder/decoder
│       ├── Validation.h / .cpp  # 7-step validation pipeline
│       ├── Capability.h / .cpp  # Fixed-array capability registry
│       ├── Core.h / Core.cpp    # Protocol engine, JSON, orchestrator
│       ├── HXTPClient.h / .cpp  # Arduino client (WiFi, MQTT, state machine)
│       ├── PlatformESP32.h/.cpp # ESP32: NVS, HW RNG, SNTP
│       ├── PlatformESP8266.h    # ESP8266: EEPROM, SW RNG, configTime
│       └── StorageNVS.h         # ESP32 NVS storage adapter
└── .github/workflows/
    └── build.yml            # CI: matrix build + size guardrails
```

## Provisioning Flow

1. **Device boots** with pre-shared `DEVICE_SECRET` (64-char hex) and
   `DEVICE_ID`.
2. **WiFi → NTP sync** (Required for timestamp validation) → **TLS** → **MQTT
   connect**.
3. **HELLO handshake**:
   - Publishes signed/HMACed JSON to
     `hxtp/{tenant_id}/device/{device_id}/hello`.
   - Includes `firmware_version`, `device_type`, `chip_id`, and
     `capabilities[]`.
4. **Subscriptions**:
   - `hxtp/{tenant_id}/device/{device_id}/cmd` (Incoming commands)
   - `hxtp/{tenant_id}/device/{device_id}/ota` (Firmware updates)
5. **Steady State**:
   - Heartbeats every 30s (Signed).
   - Telemetry/State reports (Signed).
   - Commands require valid HMAC + nonce + sequence verification.

## Security Constraints

| Constraint                  | Enforcement                                   |
| --------------------------- | --------------------------------------------- |
| **Mandatory Signatures**    | All inbound/outbound messages must be signed  |
| **FROZEN Canonical Format** | 10-field pipe-delimited string (MCSS v3.0)    |
| **Anti-Replay**             | 600s Nonce cache + Monotonic sequence         |
| **No Heap in loop()**       | All buffers stack-allocated or static         |
| **Fail-Closed Validation**  | Any pipeline step failure → reject            |
| **Constant-Time Compare**   | `crypto::constant_time_hex_equal()`           |
| **TLS Strict Mode**         | `setInsecure()` blocked in RELEASE builds     |
| **OTA Integrity**           | Mandatory Ed25519 signatures (Cloud enforced) |

## License

MIT License — Copyright (c) 2026 Hestia Labs
