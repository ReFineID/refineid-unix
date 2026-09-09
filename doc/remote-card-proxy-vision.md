# ReFineID Remote Card Proxy & 6-Digit Pairing Architecture Vision

- **Document Version**: `26.8.27.1`
- **Protocol Version**: `26.8`
- **Status**: Target Architecture & Design Vision
- **Applies To**: `ReFineID-Unix` (Linux/BSD), `ReFineID-Apple` (iOS/macOS), `ReFineID-Android`

---

## 1. Executive Summary

The **ReFineID Remote Card Proxy** enables laptops and desktops (Linux, macOS) to perform high-assurance smartcard authentication (e.g. FINEID Citizen Identity, Suomi.fi, eIDAS services) using a smartphone (iPhone, Android) as a wireless NFC card reader proxy.

### Core Tenets

1. **No Hardware Card Readers Required on Laptops**: Modern laptops rarely have smartcard slots. Instead of requiring USB CCID dongles, the user taps their physical ID card against their phone's built-in NFC radio.
2. **No QR Codes — Simple 6-Digit Numeric Pairing**: Pairing a desktop with a mobile device uses a clean 6-digit numeric pairing code (e.g. `482 915`) displayed on the desktop and entered on the mobile screen.
3. **Strict Separation of Concerns**:
   * **ReFineID Application / CLI**: Manages one-time pairing ceremonies, local vault persistence, and device lifecycle.
   * **PKCS#11 / CryptoTokenKit Module**: In-process driver loaded into browsers (Firefox, Chrome, Safari). Headless, fast, and stateless: reads paired devices from the vault, exposes virtual card slots, and dispatches signature requests on demand.
4. **Noise Cryptography Over Untrusted Transports**: End-to-end authenticated encryption (`Noise_XXpsk3` for pairing, `Noise_KK` for sessions) using Curve25519, ChaCha20-Poly1305, and SHA-256 over BLE L2CAP and Local TCP streams. The transport layer is treated as an untrusted wire.
5. **Aggressive In-Memory Certificate Caching**: Certificates (leaf authentication certificate, issuing CA, root CA) are read once from the card and cached in the local vault and RAM to eliminate slow NFC roundtrips during routine browser browsing.

---

## 2. System Architecture & Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DESKTOP / LAPTOP                              │
│                                                                         │
│  ┌───────────────────────────────┐     ┌─────────────────────────────┐  │
│  │   ReFineID App / CLI          │     │    Web Browser (Firefox)    │  │
│  │   ($ refineid pair)           │     │    Loads librefineid_pkcs11 │  │
│  └──────────────┬────────────────┘     └──────────────┬──────────────┘  │
│                 │ One-time Pairing                    │ C_Sign / Login  │
│                 ▼                                     ▼                 │
│         ┌───────────────┐                     ┌───────────────┐         │
│         │  Local Vault  │ ◄───────────────────│ PKCS#11 State │         │
│         │  (CBOR / OS)  │    Reads pairings   │ (Virtual Slot)│         │
│         └───────────────┘                     └───────┬───────┘         │
└───────────────────────────────────────────────────────┼─────────────────┘
                                                        │
                      Noise_KK Encrypted Channel        │
                 (BLE L2CAP CoC / Local Network TCP)    │
                                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           MOBILE PHONE (iOS / Android)                  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │   ReFineID Mobile App (RAPP Server)                               │  │
│  │   1. Receives `BrowserAuthenticate` request                        │  │
│  │   2. Displays prompt: "Authenticate to Suomi.fi? [Confirm]"        │  │
│  │   3. Drives NFC session: prompts user to tap physical card         │  │
│  │   4. Transmits APDUs (SELECT -> VERIFY PIN1 -> PSO COMPUTE SIG)   │  │
│  │   5. Returns card signature over Noise channel                    │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │ Contactless ISO 7816 APDUs       │
│                                      ▼                                  │
│                          ┌───────────────────────┐                      │
│                          │  Physical FINEID Card │                      │
│                          └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. One-Time 6-Digit Pairing Ceremony

### 3.1 Pairing Flow

1. **Initiation**: User runs `refineid pair` (CLI) or clicks **"Pair New Mobile"** in the ReFineID Desktop GUI.
2. **Discovery**:
   * Desktop begins advertising the ReFineID service over **Bluetooth Low Energy (BLE)** and/or **local mDNS**.
   * Desktop generates a cryptographically random 6-digit code:
     ```
     ========================================
       ReFineID Device Pairing
       Pairing Code:  4 8 2   9 1 5
     ========================================
     ```
3. **Mobile Connection**:
   * Mobile app discovers the nearby laptop name (e.g. *"Petri's Laptop"*).
   * Mobile prompts: *"Enter the 6-digit pairing code shown on your laptop"*.
4. **Mutual Authentication (`Noise_XXpsk3`)**:
   * The 6-digit code is expanded into the 32-byte pre-shared key (`psk3`) via HKDF-SHA256.
   * Mobile and Desktop perform a 3-message `Noise_XXpsk3` handshake.
   * Both devices exchange and authenticate their static Curve25519 public keys.
5. **Initial Certificate Sync & Vault Storage**:
   * Mobile prompts the user to tap their ID card once.
   * Desktop retrieves and stores:
     * Mobile's static public key and device metadata.
     * Card's authentication certificate (`EF.4331`) and on-card CA certificates (`EF.4334`..`EF.4336`).
   * The pair record is committed to the local encrypted vault (`RappDeviceVault`).

---

## 4. Routine Web Login (PKCS#11 Integration)

Once paired, the user never needs to re-enter pairing codes.

1. **Slot Enumeration**:
   * When Firefox opens, `librefineid_pkcs11.so` checks `RappDeviceVault`.
   * Each active paired phone is exposed as a PKCS#11 slot (e.g. `Slot 1: iPhone 15 Pro (ReFineID Token)`).
2. **Zero-Latency Attribute Lookups**:
   * NSS queries `CKA_VALUE`, `CKA_ISSUER`, `CKA_SUBJECT`, and CA trust anchors.
   * The PKCS#11 module answers directly from the in-memory cache without waking up the phone or card.
3. **Sign Request Dispatch**:
   * When the TLS client authentication handshake reaches the CertificateVerify step:
   * PKCS#11 module connects to the mobile proxy over `Noise_KK` (relying on pre-shared static keys).
   * Module sends a `CardOperation::BrowserAuthenticate` message containing:
     * Request Origin (`"https://www.suomi.fi"`)
     * Key Profile (`"eccP384"` / `"rsa3072"`)
     * SHA-384 / SHA-256 Digest
4. **Mobile Authorization & Card Execution**:
   * Phone displays authentication prompt with origin and cert details.
   * User confirms and holds ID card to phone.
   * Phone sends APDUs to card, computes cryptographic signature, and returns the result.
5. **TLS Completion**:
   * PKCS#11 module delivers the signature to NSS; Firefox completes login seamlessly.

---

## 5. Security & Privacy Guarantees

* **No Plaintext on Radio**: All communication over BLE or Local Wi-Fi is sealed with ChaCha20-Poly1305 and unique sequential nonces.
* **No Telemetry / No Call-Home**: Pairing and signing are 100% local point-to-point operations. No external cloud servers or relays are involved.
* **No Unattended Signing**: The phone requires user confirmation and active physical NFC card presentation for every signature operation.
* **Anti-Tracking**: BLE advertisements use rotating Resolvable Private Addresses (RPA) without transmitting device names, card numbers, or user identity in plaintext beacons.
