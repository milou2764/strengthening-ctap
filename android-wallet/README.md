# Android wallet (authenticator)

A standalone passkey wallet that acts as a FIDO2 authenticator over the CTAP
hybrid transport (caBLE v2), and implements the client-authentication
countermeasure. Package `com.example.ctapwallet`.

It performs CTAP itself (it does **not** modify the Android platform
authenticator — see the limitation note in the top-level README).

## Requirements

- A **physical** Android phone (min SDK 30). Emulators have no real BLE.
- Android SDK; set `sdk.dir` in `local.properties` (not committed).

## Build & install

```bash
./gradlew :app:installDebug
```

Launch **CTAP Wallet** on the phone.

## Use

**Enroll a client** (one-time per browser):

1. Tap *Enroll a new client*.
2. On the desktop, open `chrome://ctap-enrollment` in the address bar.
3. The client connects over BLE and shows a 6-digit code; confirm it on the
   phone only if the two codes match. The client's public key is stored in the
   trust store.

**Sign in / register** (the CTAP hybrid ceremony):

1. On a WebAuthn site (e.g. `webauthn.io`), choose the phone/hybrid option; the
   browser shows a QR code.
2. Tap *Scan QR code (sign in / register)* and scan it.
3. The wallet runs the tunnel + Noise handshake, verifies the client's
   per-session assertion, then serves `makeCredential` / `getAssertion`.

The **Require client authentication** checkbox (on by default) enforces the
countermeasure: a session whose client does not present a valid, enrolled
assertion is aborted.

## Layout

All caBLE / CTAP logic is under `app/src/main/java/com/example/ctapwallet/`:

- `cable/` — the CTAP hybrid authenticator: `DigitCoder`, `KeyDerivation`,
  `EcUtil`, `Noise`, `HandshakeHandler`, `Crypter` (transport), `CableAdvertiser`
  (0xFFF9 advert), `CableTunnel` (tunnel + CTAP serving), `PasskeyStore`,
  `QrScanActivity`, and `ClientAuthVerifier` (the countermeasure check).
- `EnrollmentGattServer`, `BleEnrollmentAdvertiser`, `ClientTrustStore`,
  `MainActivity` — the enrollment side (direct BLE + numeric comparison).
