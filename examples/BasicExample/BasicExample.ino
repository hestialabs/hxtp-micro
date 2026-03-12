
#include <HXTP.h>

// ---- WiFi Configuration ----
static const char* WIFI_SSID     = "YOUR_SSID";
static const char* WIFI_PASS     = "YOUR_PASSWORD";

// ---- MQTT Broker Configuration ----
static const char* MQTT_HOST     = "mqtt.example.com";
static const uint16_t MQTT_PORT  = 8883;

// ---- HXTP Configuration ----
static const char* TENANT_ID     = ""; // UUID of your tenant
static const char* DEVICE_SECRET = ""; // 64-character hex secret

static const char* ROOT_CA = R"(
-----BEGIN CERTIFICATE-----
MIID...==
-----END CERTIFICATE-----
)";

// ---- Pin Configuration ----
static const int LED_PIN = 2;  // GPIO2 for ESP32, D2 for ESP8266

// ---- Global Variables ----
static HXTPConfig config;
static hxtp::HXTPClient* client = nullptr;

// ---- Capability Handler ----
// Example handler for a "set_pin" capability
HxtpCapabilityResult handle_set_pin(const char* params, uint32_t len, void*) {
  HxtpCapabilityResult result{};
  
  int64_t pin = 0, value = 0;
  
  if (!hxtp::json_get_int64(params, len, "pin", &pin) ||
      !hxtp::json_get_int64(params, len, "value", &value)) {
    result.success = false;
    result.error_code = static_cast<int16_t>(HxtpError::INVALID_PARAMS);
    snprintf(result.error_msg, sizeof(result.error_msg), "Missing pin or value");
    return result;
  }
  
  pinMode(static_cast<uint8_t>(pin), OUTPUT);
  digitalWrite(static_cast<uint8_t>(pin), value ? HIGH : LOW);
  
  result.success = true;
  return result;
}

// ---- Error Callback ----
void on_hxtp_error(HxtpError err, const char* msg, void*) {
  Serial.printf("[HXTP] ERROR %d: %s\n", static_cast<int>(err), msg ? msg : "Unknown");
}

// ---- Setup ----
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n[HXTP] Basic Example - Starting...");
  
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  // Configure HXTP client
  config.wifi_ssid     = "MyWiFiNetwork";
  config.wifi_password = "SuperSecretPassword";

  /* Provisioning Payload configuration */
  config.api_base_url  = "https://api.hestialabs.com/api/v1";
  config.device_id     = "d123456789abcdef0123456789abcdef";
  config.tenant_id     = "t-987654321";
  
  // In production, the device secret should be loaded from secure storage.
  // Setting it here for demonstration.
  config.device_secret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  
  config.ca_cert          = ROOT_CA;
  config.verify_server    = true;
  config.firmware_version = "1.0.0";
  config.device_type      = "smart_switch";
  
  // Create HXTP client instance
  client = new hxtp::HXTPClient(config);
  client->onError(on_hxtp_error, nullptr);
  
  // Initialize HXTP
  HxtpError err = client->begin();
  if (err != HxtpError::OK) {
    Serial.printf("[HXTP] FATAL: %s\n", hxtp_error_str(err));
    while (true) {
      delay(1000);
    }
  }
  
  // Register capability handler
  client->registerCapability(1, "set_pin", handle_set_pin);
  
  // Print device ID and connect
  Serial.printf("[HXTP] Device ID: %s\n", client->deviceId());
  client->connect();
}

// ---- Loop ----
void loop() {
  // Service the HXTP client (handles WiFi, MQTT, protocol messages)
  if (client != nullptr) {
    client->loop();
  }
  
  // Small delay to prevent watchdog reset
  delay(10);
}
