# HXTP Embedded SDK v1.0

> HxTP/2.2 protocol implementation for ESP32 and ESP8266 IoT devices.  
> PlatformIO-native · Arduino framework · Zero dynamic allocation in hot path.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Application  (app/main.cpp or examples/*)                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  #include <HXTP.h>    ← single public entry point         │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  HXTPClient  (HXTPClient.h)                         │  │  │
│  │  │  ┌──────────┐ ┌────────────┐ ┌──────────────────┐  │  │  │
│  │  │  │  Frame    │ │  Crypto    │ │  Validation      │  │  │  │
│  │  │  │ Encoder/  │ │ SHA-256    │ │ 7-Step Pipeline  │  │  │  │
│  │  │  │ Decoder   │ │ HMAC-256   │ │ 1. Version       │  │  │  │
│  │  │  │          │ │ AES-GCM    │ │ 2. Timestamp     │  │  │  │
│  │  │  │          │ │ Const-Time │ │ 3. Payload Size  │  │  │  │
│  │  │  └──────────┘ └────────────┘ │ 4. Nonce         │  │  │  │
│  │  │  ┌──────────┐ ┌──────────┐   │ 5. Payload Hash  │  │  │  │
│  │  │  │Capability│ │  JSON    │   │ 6. Sequence      │  │  │  │
│  │  │  │ Registry │ │ Parser   │   │ 7. HMAC Sig      │  │  │  │
│  │  │  │ (32 max) │ │ (zero-  │   └──────────────────┘  │  │  │
│  │  │  │          │ │  alloc)  │                         │  │  │
│  │  │  └──────────┘ └──────────┘                         │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌───────────────────────────────────────────────────┐    │  │
│  │  │  Platform Layer                                    │    │  │
│  │  │  ┌───────────────┐ ┌───────────────┐              │    │  │
│  │  │  │ ESP32          │ │ ESP8266        │              │    │  │
│  │  │  │ • mbedTLS      │ │ • BearSSL      │              │    │  │
│  │  │  │ • NVS Storage  │ │ • EEPROM       │              │    │  │
│  │  │  │ • HW RNG       │ │ • SW RNG       │              │    │  │
│  │  │  │ • SNTP         │ │ • configTime   │              │    │  │
│  │  │  │ • WiFiSecure   │ │ • WiFiSecure   │              │    │  │
│  │  │  └───────────────┘ └───────────────┘              │    │  │
│  │  └───────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Supported Boards

| Board             | Platform       | Crypto Backend | RAM Usage | Flash Usage |
| ----------------- | -------------- | -------------- | --------- | ----------- |
| ESP32-S3 DevKit   | espressif32    | mbedTLS        | 13.8%     | 29.6%       |
| ESP32 DevKit v1   | espressif32    | mbedTLS        | 13.9%     | 51.7%       |
| NodeMCU v2        | espressif8266  | BearSSL        | 39.5%     | 39.6%       |
| Wemos D1 Mini     | espressif8266  | BearSSL        | 39.5%     | 39.6%       |

## Quick Start (PlatformIO)

### 1. Add the library

In your `platformio.ini`:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps =
    HXTP
    knolleary/PubSubClient@^2.8
build_flags =
    -std=gnu++17
    -DHXTP_RELEASE=1
```

### 2. Include the SDK

```cpp
#include <HXTP.h>
```

That's it — one header gives you everything: `HXTPConfig`, `HXTPClient`, `HxtpError`, all types.

### 3. Configure & Connect

```cpp
HXTPConfig config;
config.wifi_ssid     = "MyWiFi";
config.wifi_password = "MyPassword";
config.mqtt_host     = "mqtt.example.com";
config.mqtt_port     = 8883;
config.ca_cert       = ROOT_CA_PEM;
config.verify_server = true;
config.tenant_id     = "your-tenant-uuid";
config.device_secret = "64-char-hex-secret";
config.firmware_version = "1.0.0";
config.device_type   = "my-sensor";

hxtp::HXTPClient client(config);
client.begin();
client.registerCapability(1, "set_pin", my_handler);
client.connect();
```

### 4. Main Loop

```cpp
void loop() {
    client.loop();  // handles MQTT, heartbeats, commands
    delay(10);
}
```

### 5. Capability Handler

```cpp
HxtpCapabilityResult my_handler(const char* params, uint32_t len, void* ctx) {
    HxtpCapabilityResult r{};
    int64_t val = 0;
    if (!hxtp::json_get_int64(params, len, "value", &val)) {
        r.success = false;
        r.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
        snprintf(r.error_msg, sizeof(r.error_msg), "Missing value");
        return r;
    }
    digitalWrite(LED_BUILTIN, val ? HIGH : LOW);
    r.success = true;
    return r;
}
```

## Examples

| Example                   | Description                           | Target   |
| ------------------------- | ------------------------------------- | -------- |
| `SingleNode/main.cpp`     | Single LED capability + telemetry     | ESP32    |
| `MultiRelay/main.cpp`     | 4-channel relay with state reporting  | ESP32    |
| `ESP8266Node/main.cpp`    | Constrained sensor node               | ESP8266  |
| `WemosD1Mini/main.cpp`    | DHT sensor + LED on D1 Mini           | ESP8266  |
| `GenericWiFi/main.cpp`    | Minimal skeleton for any WiFi board   | Any      |

## Memory Footprint

| Component           | Flash   | RAM (static) | RAM (stack)   |
| ------------------- | ------- | ------------ | ------------- |
| Core types/errors   | ~2 KB   | 0            | 0             |
| Frame encoder       | ~1 KB   | 0            | 0             |
| Crypto (mbedTLS)    | ~8 KB   | 0            | ~2 KB/call    |
| Crypto (BearSSL)    | ~4 KB   | 0            | ~1 KB/call    |
| Validation pipeline | ~3 KB   | ~5 KB*       | ~1 KB/call    |
| JSON parser         | ~2 KB   | 0            | ~512 B/call   |
| Capability registry | ~1 KB   | ~1.5 KB†     | 0             |
| HXTPClient          | ~4 KB   | ~8 KB‡       | ~512 B        |
| **Total (ESP32)**   | **~21 KB** | **~14.5 KB** | **~4 KB peak** |
| **Total (ESP8266)** | **~17 KB** | **~11 KB**   | **~3 KB peak** |

\* Nonce cache: 64 entries × 60 bytes = ~3.8 KB (32 entries on ESP8266)  
† 32 capability slots × 48 bytes = ~1.5 KB (16 on ESP8266)  
‡ TX buffer (4 KB) + ACK buffer (1 KB / 512 B on ESP8266) + TLS + MQTT  

## Protocol Compliance

| Feature                     | Status |
| --------------------------- | ------ |
| HxTP/2.2 version tag        | ✅     |
| Binary framing (8-byte hdr) | ✅     |
| HMAC-SHA256 signatures      | ✅     |
| SHA-256 payload hash         | ✅     |
| Canonical string (FROZEN)    | ✅     |
| Nonce replay protection      | ✅     |
| Sequence monotonicity        | ✅     |
| Timestamp freshness          | ✅     |
| Constant-time comparison     | ✅     |
| Dual-key rotation fallback   | ✅     |
| AES-256-GCM secret storage   | ✅     |
| MQTT QoS 1                   | ✅     |
| TLS 1.2+                     | ✅     |
| 30s heartbeat interval       | ✅     |

## File Structure

```
SDK/C++/
├── platformio.ini               # Build targets: esp32s3, esp32, esp8266
├── app/
│   └── main.cpp                 # Default application
├── lib/HXTP/
│   ├── library.json             # PlatformIO library metadata
│   └── src/
│       ├── HXTP.h               # ← Umbrella header (public entry point)
│       ├── Config.h             # Stability contract, feature flags, tunables
│       ├── Types.h              # Protocol constants, types, HXTPConfig
│       ├── Errors.h             # Error codes (match server enum)
│       ├── HXTPCrypto.h         # Crypto interface (SHA-256, HMAC, AES-GCM)
│       ├── CryptoMbedTLS.cpp    # ESP32 crypto implementation (mbedTLS)
│       ├── CryptoBearSSL.cpp    # ESP8266 crypto implementation (BearSSL)
│       ├── Frame.h / Frame.cpp  # Binary frame encoder / decoder
│       ├── Validation.h / .cpp  # 7-step validation pipeline
│       ├── Capability.h / .cpp  # Fixed-array capability registry
│       ├── Core.h / Core.cpp    # Protocol engine, JSON, orchestrator
│       ├── HXTPClient.h / .cpp  # Arduino client (WiFi, MQTT, state machine)
│       ├── PlatformESP32.h/.cpp # ESP32: NVS, HW RNG, SNTP
│       ├── PlatformESP8266.h    # ESP8266: EEPROM, SW RNG, configTime
│       └── StorageNVS.h         # ESP32 NVS storage adapter
├── examples/
│   ├── SingleNode/main.cpp      # ESP32 single-capability node
│   ├── MultiRelay/main.cpp      # ESP32 4-channel relay
│   ├── ESP8266Node/main.cpp     # ESP8266 constrained sensor
│   ├── WemosD1Mini/main.cpp     # Wemos D1 Mini sensor
│   └── GenericWiFi/main.cpp     # Generic WiFi board skeleton
└── .github/workflows/
    └── sdk-build.yml            # CI: matrix build + size guardrails
```

## Provisioning Flow

```
1. Device boots with pre-shared DEVICE_SECRET (64-char hex)
   → Secret loaded from NVS (ESP32) or EEPROM (ESP8266) or config

2. WiFi → NTP sync → TLS → MQTT connect
   → Client ID: hxtp-{device_id}

3. HELLO handshake
   → Publishes to: hxtp/{tenant_id}/device/{device_id}/hello
   → Includes firmware_version, device_type, capabilities[]

4. Subscribes to:
   → hxtp/{tenant_id}/device/{device_id}/cmd
   → hxtp/{tenant_id}/device/{device_id}/ota

5. Heartbeats every 30s
   → hxtp/{tenant_id}/device/{device_id}/heartbeat
   → Server timeout: 120s

6. Commands arrive on cmd topic
   → Frame decode → JSON parse → 7-step validation → capability dispatch
   → ACK on: hxtp/{tenant_id}/device/{device_id}/cmd_ack
```

## Build Profiles

| Profile               | Flag                  | Description                           |
| --------------------- | --------------------- | ------------------------------------- |
| **Release** (default) | `-DHXTP_RELEASE=1`    | Full security, no debug output        |
| Debug                 | `-DHXTP_DEBUG=1`      | Serial logging, optional `setInsecure()` |
| Lite                  | `-DHXTP_LITE=1`       | Reduced nonce cache (32 entries)      |
| Constrained           | `-DHXTP_CONSTRAINED=1`| Auto-set on ESP8266: smaller buffers  |

## Security Constraints

| Constraint                          | Enforcement                              |
| ----------------------------------- | ---------------------------------------- |
| No `Arduino String`                 | All strings use `FixedStr<N>` or `char[]` |
| No heap in `loop()`                 | All buffers stack-allocated or static    |
| No dynamic allocation in hot path   | Capability array, nonce cache are static |
| Fail-closed validation              | Any pipeline step failure → reject       |
| Constant-time signature compare     | `crypto::constant_time_hex_equal()`      |
| Max 16 KB payload                   | Enforced at frame decode AND validation  |
| `setInsecure()` blocked in RELEASE  | Compile-time `#error` if not DEBUG mode  |
| No TODOs / placeholders in release  | Enforced by CI scan                      |

## CI / Guardrails

The CI pipeline (`.github/workflows/sdk-build.yml`) enforces:

- **All 3 targets must compile**: esp32s3, esp32, esp8266
- **Flash ≤ 85%** per target
- **RAM ≤ 50%** per target
- Matrix build on every push/PR to `main`

## License

MIT License — Copyright (c) 2026 Hestia Labs
