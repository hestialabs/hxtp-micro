# HxTP Protocol Specification v3.1.0 (Canonical)

**Target:** Embedded Runtimes, Cloud Orchestration, AI Agents  
**Governance:** Hestia Labs

---

## 1. Framing Architecture

HxTP uses a deterministic binary framing layer to minimize parsing overhead on constrained devices.

### 1.1 Binary Frame Header (8 Bytes)
All messages begin with a fixed 8-byte header:

| Offset | Size | Name | Description |
| :--- | :--- | :--- | :--- |
| 0 | 2 | MAGIC | Fixed magic bytes: `0x48 0x58` ("HX") |
| 2 | 1 | VERSION | Framer version (Current: `0x03`) |
| 3 | 1 | TYPE | Message type code (see Section 1.2) |
| 4 | 4 | PAYLOAD_LEN | Length of payload in Big-Endian |

### 1.2 Message Type Codes
| Code | Name | Description |
| :--- | :--- | :--- |
| `0x01` | STATE | Device state broadcast |
| `0x02` | COMMAND | Remote execution request |
| `0x03` | ACK | Command/Request acknowledgement |
| `0x04` | HEARTBEAT | Liveness signal |
| `0x05` | TELEMETRY | Sensor/Metric data |
| `0x06` | OTA | Firmware update control |
| `0x07` | ERROR | Protocol error signal |
| `0x08` | HELLO | Runtime registration/Handshake |

---

## 2. Cryptographic Identity & Signing

### 2.1 Root Identity
- **Mechanism:** Firmware-generated Ed25519 keypair.
- **Generation:** Performed on first boot. Private key MUST NOT be exportable.
- **Device ID:** Hex-encoded Ed25519 public key (32 bytes -> 64 chars).

### 2.2 Canonical Signing Format
The signature is computed over a pipe-separated string of message metadata.

**Format:**
`version|device_id|tenant_id|client_id|message_id|request_id|sequence|timestamp|nonce|message_type|payload_hash`

- **Separator:** `|` (Pipe)
- **Hashing:** `payload_hash` is the SHA-256 hex digest of the raw payload.
- **Signature:** HMAC-SHA256 (Session) or Ed25519 (Identity-bound).

### 2.3 No JSON Canonicalization
Recursive JSON sorting and whitespace normalization are FORBIDDEN. The `payload_hash` MUST be computed on the raw bytes of the payload as transmitted.

---

## 3. Device Lifecycle

Devices MUST strictly transition through the following states:

1. **BOOTSTRAP:** Local-only. WiFi setup. Identity generation.
2. **PENDING_CLAIM:** Identity registered in cloud, awaiting owner association.
3. **CLAIMED:** Ownership established. No active runtime session.
4. **ACTIVE:** Authenticated MQTT session. Signed HELLO validated.
5. **REVOKED:** Permanently disabled.

---

## 4. Replay & Security Policy

### 4.1 Replay Protection
- **Nonce Cache:** Minimum 128 entries.
- **Timestamp Skew:** Max 30,000ms (30s) allowance.
- **Sequence:** Strictly monotonic per session. Rollover MUST trigger re-bootstrap.

### 4.2 MQTT Authentication
- **Mechanism:** Short-lived session tokens.
- **Issuance:** Provided by Cloud Bootstrap endpoint.
- **Rotation:** Expired tokens MUST cause client disconnection and re-bootstrap.

---

## 5. Provisioning & Claiming

### 5.1 Local Discovery
`GET /device/info` exposes:
- Public Key
- Firmware Version
- Signed Ephemeral Claim Token

### 5.2 Signed Claim Token
Tokens MUST be ephemeral and signed by the device:
`device_id|pub_key|nonce|timestamp|expiry|signature` (Ed25519)

---

## 6. MQTT Topic Structure

Topics are isolated by `tenant_id`:
- `hxtp/{tenant_id}/device/{device_id}/state`
- `hxtp/{tenant_id}/device/{device_id}/cmd`
- `hxtp/{tenant_id}/device/{device_id}/cmd_ack`
- `hxtp/{tenant_id}/device/{device_id}/hello`
- `hxtp/{tenant_id}/device/{device_id}/heartbeat`
- `hxtp/{tenant_id}/device/{device_id}/telemetry`

---

## 7. Security Invariants

- **Fail-Closed:** Any validation failure (signature, nonce, skew) MUST result in message rejection.
- **Watchdog:** Protocol execution MUST NOT block the system watchdog.
- **Memory:** Zero-allocation or bounded static buffers ONLY.
- **Downgrade Protection:** Protocol version 3.0 or below MUST be rejected.

---

## 8. Architectural Trust Boundaries

### 8.1 Runtime Descriptor Trust
The `RuntimeDescriptor` (platform, board, mcu, etc.) is **INFORMATIONAL ONLY**. It provides telemetry and operational context but MUST NOT be used for authorization, RBAC, or capability enforcement. Cloud systems must assume descriptors can be spoofed by malicious firmware.

### 8.2 OTA Trust Model
- **Root Authority:** The SDK MUST enforce a root OTA public key for manifest verification.
- **Manifest Signing:** All OTA manifests MUST be signed. Unsigned or incorrectly signed manifests MUST be rejected (Fail-Closed).
- **Rollback Protection:** Manifests MUST include a monotonic `rollback_index`. Updates with a lower index than the current firmware MUST be rejected.
- **Trust Boundary:** OTA operations during session expiry MUST trigger a re-bootstrap before applying the update.

### 8.3 Runtime Attestation
- **Descriptor Hashing:** The entire `RuntimeDescriptor` SHOULD be hashed (SHA-256) into a `descriptor_hash` for inclusion in the `HELLO` handshake.
- **Capability Immutability:** Capabilities registered during `BOOTSTRAP` MUST be immutable once the `HELLO` handshake is complete.

### 8.4 Session Rotation & Lifecycle
- **Mid-Command Expiry:** If a session expires during a long-running command, the client MUST finish the execution and re-bootstrap before sending the `ACK`.
- **OTA Transition:** If a session invalidation occurs during an OTA download, the client SHOULD re-bootstrap to maintain the secure channel before applying the final binary.
- **Reboot Persistence:** Cloud-issued `tenant_id` and `mqtt_session_token` SHOULD be persisted across reboots to avoid redundant bootstrap cycles.
