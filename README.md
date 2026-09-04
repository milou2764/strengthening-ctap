# Client Authentication for CTAP Hybrid Transport

Defending cross-device authentication (FIDO2 / WebAuthn caBLE v2) against
**unauthorized clients**. This monorepo holds the research paper, the formal
models, and a working end-to-end prototype of the countermeasure.

The root problem: in the CTAP 2 hybrid transport, an authenticator (e.g. a
phone) has **no way to tell which client** (browser) it is talking to. An
attacker who relays a QR code can make a victim's authenticator complete a
ceremony for the attacker's session. Our countermeasure gives the client a
persistent identity that the authenticator enrolls once and then verifies on
every session.

The design rests on two phases:

1. **Enrollment (one-time).** The client and authenticator establish a shared
   trust anchor over a **direct BLE connection with numeric comparison** — no
   server, no broadcast nonce, no QR, no typed secret. The user starts
   enrollment on the authenticator, opens `chrome://ctap-enrollment` in the
   browser's address bar (a non-spoofable origin), the client connects directly
   over BLE and sends its public identity key, and both devices display a
   6-digit code the user confirms. Security rests on exactly three assumptions:
   a trusted authenticator, a trusted client platform, and the user opening the
   URL in the address bar. **No trusted-network assumption.**

2. **Authentication (every session).** During the normal CTAP hybrid ceremony,
   the client sends a per-session **COSE_Sign1** signed by its enrolled identity
   key, binding the session's Noise **handshake hash** and a timestamp. The
   authenticator verifies it against its trust store and **aborts the session**
   if no enrolled client key matches.

This prototype is implemented and **works end-to-end** against real relying
parties over the full CTAP hybrid transport.

## Repository layout

| Path | What |
|---|---|
| [`paper/`](paper/) | The IEEE Access paper (LaTeX) and its figures. Run `paper/build.sh` to compile `main.pdf`. |
| [`models/`](models/) | PlantUML sequence diagrams (`puml/`) and SPIN/Promela formal models (`promela/`). |
| [`android-wallet/`](android-wallet/) | The **authenticator**: an Android passkey wallet that performs CTAP hybrid, enrolls clients, and verifies the per-session client assertion. |
| [`chromium/`](chromium/) | The **client**: modifications to Chromium — the `chrome://ctap-enrollment` page and the per-session COSE_Sign1 client authentication, on both the WebAuthn and the Digital Credentials API cross-device paths. Delivered as a patch + new files. |
| [`tools/dc-verifier/`](tools/dc-verifier/) | A one-file test verifier that requests an OpenID4VP presentation via `navigator.credentials.get({digital})`, to exercise the Digital Credentials API path. |

## Architecture

```
   ┌────────────────────────────┐        ┌────────────────────────────┐
   │ Client (Chromium)          │        │ Authenticator (Android     │
   │ chrome://ctap-enrollment   │        │ wallet)                    │
   ├────────────────────────────┤        ├────────────────────────────┤
   │ one identity key per       │        │ client trust store         │
   │ authenticator (OS store)   │        │ (enrolled public keys)     │
   └─────────────┬──────────────┘        └─────────────┬──────────────┘
                 │                                     │
                 │  1. Enrollment: direct BLE +        │
                 │     committed 6-digit comparison    │
                 │◄───────────────────────────────────►│
                 │                                     │
                 │  2. Authentication: CTAP hybrid     │
                 │     QR → BLE advert → tunnel →      │
                 │     Noise handshake                 │
                 │  ── per-session COSE_Sign1 ────────►│ verify vs trust
                 │     (binds handshake hash)          │ store, else ABORT
                 │                                     │
```

## Quick start

Two devices are required: a desktop running the modified Chromium and a physical
Android phone running the wallet (a real phone is needed — emulators have no BLE).

1. **Build & install the authenticator** — see [`android-wallet/README.md`](android-wallet/README.md).
2. **Build the modified client** — see [`chromium/README.md`](chromium/README.md).
3. **Enroll the client:** on the phone tap *Enroll a new client*, open
   `chrome://ctap-enrollment` on the desktop, then type the 6-digit code shown
   by the page into the phone (a wrong code aborts the enrollment).
4. **Use it:** launch Chromium with the feature flag, go to a WebAuthn site
   (e.g. `webauthn.io`), choose the phone/hybrid option, and scan the QR with the
   wallet's *Scan QR code* button. With *Require client authentication* on, an
   un-enrolled client is rejected.
5. **Digital Credentials API:** serve `tools/dc-verifier/` on localhost
   (`python3 -m http.server 8765`), open `http://localhost:8765/` in the modified
   Chromium, click *Request credential*, and scan the QR **from inside the wallet**
   (the phone's camera app hands the QR to the Android platform authenticator
   instead, which does not answer digital-credential requests).

## Status

- Enrollment (BLE + numeric comparison): **working**, confirmed end-to-end.
- Authentication (per-session COSE_Sign1 over real CTAP hybrid): **working**,
  confirmed end-to-end (passkey registration and assertion against `webauthn.io`).
- Digital Credentials API cross-device flow (OpenID4VP request as a type-3 JSON
  message over the same authenticated session): **working**, confirmed end-to-end
  against the local test verifier.
- Measured cost (see [`tools/measurements/`](tools/measurements/)): enrollment
  ≈1.8 s end-to-end of which the committed comparison is ~90 ms; per session the
  client signs in ~125 µs, the 144-byte assertion frame adds no round trip, and
  the authenticator verifies it in ~1 ms.
- Formal models: SPIN verifies the enrollment and countermeasure properties (see
  [`models/`](models/)).

### Scope and limitation

The authenticator is realized as a **standalone Android wallet app that performs
CTAP itself**, rather than a modification to the Android platform authenticator.
This is a deliberate prototyping choice — it demonstrates the countermeasure
end-to-end without patching and rebuilding the OS — but a production deployment
would implement the same verification inside the platform authenticator.
