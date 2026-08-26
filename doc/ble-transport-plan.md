# Bluetooth Low Energy (BLE) Transport Profile Architecture & Implementation Plan

- **Document Version**: `26.8.26.135`
- **Protocol Wire Version**: `26.8`
- **Target Profile Identifier**: `fi.refineid.ble.v1`
- **Status**: Vetted Architecture & Implementation Plan
- **Date**: 2026-08-26
- **Applies To**: `ReFineID-Apple` (iOS/macOS), `ReFineID-Unix` (Linux), `ReFineID-Android`

---

## 1. Executive Summary & Feasibility Verdict

### 1.1 Feasibility Verdict
**Bluetooth Low Energy (BLE) is fully feasible, practical, and highly complementary to local LAN.**

It provides a point-to-point wireless underlay between the **Requester** (Mac, Linux) and the **Authorization Proxy** (iPhone) that operates in coffee shops, trains, public Wi-Fi with client isolation, and mobile tethering environments without requiring a shared local router or subnet.

### 1.2 "Secure, Not Overkill" Design Philosophy
To avoid over-engineering, connection fragility, and unnecessary OS pairing friction:
1. **No OS Bluetooth Bonding**: Do not require OS-level Bluetooth device pairing (no system passkey popups or bonding database state).
2. **Noise Application-Layer Cryptography**: All security is guaranteed by RAPP's existing `Noise_XXpsk3` (pairing) and `Noise_KK` (sessions) running Curve25519 and ChaCha20-Poly1305 over the BLE stream. The Bluetooth radio is treated as an untrusted wire.
3. **L2CAP Connection-Oriented Channels (CoC)**: Use native BLE L2CAP binary streaming (`CBL2CAPChannel` on iOS/macOS, L2CAP sockets on Linux BlueZ). This eliminates custom GATT fragmentation protocols and provides a clean, stream-oriented interface identical to TCP.
4. **Foreground Lifecycle Alignment**: Because holding the NFC card and entering CAN/PIN1 requires an active user in the foreground anyway, BLE connections are established on-demand during active operations, avoiding iOS background execution traps.

---

## 2. Protocol Wire Specification (`fi.refineid.ble.v1`)

### 2.1 Transport Framing
Like the TCP stream profile (`fi.refineid.stream.v1`), every RAPP frame over BLE consists of:
- **2-byte big-endian length prefix** ($N \le 65,535$).
- **$N$ bytes of payload** (Noise handshake message or Noise transport envelope).

### 2.2 Transport Underlay: L2CAP CoC
- **Primary Channel**: L2CAP Connection-Oriented Channel (PSM dynamically assigned by Proxy or advertised via standard GATT service).
- **Packet Handling**: The Bluetooth baseband controller handles hardware segmentation and reassembly (up to 64 KiB SDUs).
- **Throughput & Latency**: A complete ~200-byte signing request and ~512-byte signature round-trip takes $< 30\text{ ms}$ over BLE 4.2/5.0 Data Length Extension.

### 2.3 GATT Service & Discovery Layout (Fallback / Bootstrap)

```
Primary Service UUID: FA1D0001-C34A-4836-843B-7603B5749A32 (ReFineID RAPP Service)

Characteristics:
├── L2CAP PSM Characteristic (Read)
│   UUID: FA1D0004-C34A-4836-843B-7603B5749A32
│   Value: 16-bit unsigned integer PSM for direct L2CAP CoC connection
│
├── RX Stream Characteristic (Write Without Response / Fallback)
│   UUID: FA1D0002-C34A-4836-843B-7603B5749A32
│
└── TX Stream Characteristic (Notify / Fallback)
    UUID: FA1D0003-C34A-4836-843B-7603B5749A32
```

### 2.4 QR Pairing Offer Parameters
When advertising BLE support in the pairing QR code, the `transport-candidate` parameter map is:

```cddl
ble-parameters = {
  "service_uuid": tstr,             ; 128-bit ReFineID Service UUID
  ? "psm": uint                     ; L2CAP PSM if statically known
}
```

### 2.5 Rendezvous Preamble
Immediately upon L2CAP channel connection, before the Noise handshake:

```cddl
ble-rendezvous = [
  "RAPP-ble-v1",
  tstr,                             ; "pairing" or "session"
  bstr                              ; empty (for pairing) or rendezvous_token (for session)
]
```

---

## 3. Security, Privacy & Anti-Tracking Analysis

| Threat / Risk | Vetted Mitigation ("Secure, Not Overkill") |
| :--- | :--- |
| **Radio Eavesdropping** | Payload is Noise-encrypted (`Noise_XXpsk3` / `Noise_KK` with ChaCha20-Poly1305) before transmission over BLE. |
| **Device Tracking / Sniffing** | No device names, user identifiers, card numbers, or certificates are advertised in BLE beacons. Advertisements use standard rotating Resolvable Private Addresses (RPA). |
| **Man-in-the-Middle (MITM)** | The 256-bit QR pairing secret authenticates the initial pairing (`psk3`). Stored static Curve25519 keys mutually authenticate all subsequent sessions (`Noise_KK`). |
| **Replay / Injection** | Strictly sequential Noise transport nonces; any replayed, dropped, or modified frame fails Poly1305 authentication and instantly drops the session. |
| **Relay / Distance Extension** | Monotonic synchronous response timeouts (30s max for card operations) plus explicit physical authorization on the iPhone screen. |

---

## 4. Architecture in `ReFineID-Apple` & `ReFineID-Unix`

### 4.1 Apple (`ReFineID-Apple`)
- **`BleRelaySession.swift`**: Manages `CBCentralManager` (client) and `CBPeripheralManager` (server) lifecycle.
- **`BleL2CAPChannelHandler.swift`**: Wraps `CBL2CAPChannel` input/output streams into the standard `RappFrameTransport` interface.
- **`BleRelayEndpoint.swift`**: Represents Service UUID and PSM endpoints matching the QR candidate.
- **`BleRelayFraming.swift`**: Handles length-prefix boundary verification.

### 4.2 Linux (`ReFineID-Unix`)
- **`refineid-lib-core / rapp`**: Shared framing, preamble codecs, and Noise handshake.
- **`refineid-pkcs11` & CLI**: Uses BlueZ L2CAP sockets (`AF_BLUETOOTH`, `BTPROTO_L2CAP`) or D-Bus GATT service for BLE connection.

### 4.3 Transport Selection & Fallback Policy
The connection coordinator manages multi-transport failover:
1. **Parallel Probe**: Probe LAN Stream (`fi.refineid.stream.v1`) and BLE (`fi.refineid.ble.v1`) concurrently.
2. **Preference**: Use LAN if reachable within 1.5 seconds (lower latency).
3. **Fallback**: If LAN is unreachable (e.g. public Wi-Fi client isolation), seamlessly complete connection over BLE L2CAP.

---

## 5. Cross-Platform Alignment

- **Apple (`refineid-apple`)**: `CoreBluetooth` using `CBL2CAPChannel` on iOS / macOS.
- **Linux (`refineid-unix`)**: Linux BlueZ using standard L2CAP sockets (`AF_BLUETOOTH`, `BTPROTO_L2CAP`) or DBus API.
- **Android (`refineid-android`)**: `BluetoothSocket.createL2capChannel(...)` on Android 10+ (API 29+).
