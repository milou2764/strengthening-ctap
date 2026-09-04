# Chromium client modifications

The client side of the countermeasure. Two pieces:

1. **`chrome://ctap-enrollment`** — a privileged WebUI page that enrolls this
   browser with an authenticator over a direct BLE connection + numeric
   comparison. It owns a persistent per-profile identity key.
2. **Per-session client authentication** — during the CTAP hybrid (caBLE v2)
   ceremony, once the authenticator has announced its identifier in the
   post-handshake message, the browser sends an unsolicited encrypted
   `COSE_Sign1` (message type `kUpdate`) signed by the identity key it enrolled
   with that authenticator, binding the session's handshake hash and a
   timestamp. This runs on both callers of the caBLE tunnel: WebAuthn
   (`chrome/browser/webauthn`) and the Digital Credentials API cross-device
   flow (`chrome/browser/digital_credentials`,
   `content/browser/digital_credentials`).

Because a full Chromium checkout is ~100 GB, the changes ship as a **patch** for
existing files plus the **new files** added, applied onto a matching checkout.

- Base version: **Chromium 154.0.8014.0** (`chrome/VERSION`).
- `patches/ctap-client-auth.patch` — unified diff of the 22 modified files.
- `new-files/` — the 12 added files, mirrored in their source-tree paths.

## Applying to a Chromium checkout

```bash
# 1. Fetch Chromium and check out the matching version (see the Chromium docs
#    at https://www.chromium.org/developers/how-tos/get-the-code/ ). Then, from
#    this directory:
./apply.sh /path/to/chromium/src

# 2. Configure and build (16 GB RAM: use -j4).
cd /path/to/chromium/src
gn gen out/Default
autoninja -C out/Default chrome
```

### macOS note

Recent macOS requires Bluetooth-usage strings in the app's `Info.plist`, and a
dev build has none. After every (re)link, re-insert them and re-sign ad-hoc, or
Bluetooth calls abort the process:

```bash
PLIST=out/Default/Chromium.app/Contents/Info.plist
plutil -replace NSBluetoothAlwaysUsageDescription -string "CTAP enrollment" "$PLIST"
plutil -replace NSBluetoothPeripheralUsageDescription -string "CTAP enrollment" "$PLIST"
codesign --force --sign - --timestamp=none out/Default/Chromium.app
```

## Running

The per-session client authentication is behind a feature flag (disabled by
default). Enable it and keep a stable profile directory (the identity key is
stored per profile):

```bash
out/Default/Chromium.app/Contents/MacOS/Chromium \
  --enable-features=WebAuthnCtapClientIdentity \
  --user-data-dir=/tmp/ctap-profile
```

Then enroll via `chrome://ctap-enrollment`, and authenticate on any WebAuthn
site by scanning the caBLE QR with the wallet.

## What changed

New files (`new-files/`):

- `chrome/browser/webauthn/ctap_client_identity.{h,cc}` — the persistent
  per-profile client identity key (pref `webauthn.ctap_client_identity_key`).
- `chrome/browser/ui/webui/ctap_enrollment/*` — the WebUI handler, Mojo
  interface, and page controller (GATT central: connect, write the public key,
  numeric comparison).
- `chrome/browser/resources/ctap_enrollment/*` — the page's TypeScript/HTML.

Modified files (`patches/ctap-client-auth.patch`):

- `device/fido/cable/fido_tunnel_device.{h,cc}` — assembles and sends the
  post-handshake `COSE_Sign1` (`MaybeSendClientAuth`).
- `device/fido/cable/v2_discovery.{h,cc}`, `device/fido/fido_discovery_factory.{h,cc}`,
  `device/fido/public/features.{h,cc}` — plumb the identity key from the request
  delegate down to the tunnel device, gated by `kWebAuthnCtapClientIdentity`.
- `chrome/browser/webauthn/chrome_authenticator_request_delegate.cc` — registers
  the pref and supplies the key.
- WebUI wiring: `chrome/browser/ui/webui/{BUILD.gn,chrome_web_ui_configs.cc}`,
  `chrome/browser/chrome_browser_interface_binders_webui.cc`,
  `chrome/browser/resources/BUILD.gn`, `chrome/browser/webauthn/BUILD.gn`,
  `chrome/common/webui_url_constants.h`, `third_party/lit/v3_0/BUILD.gn`,
  `tools/gritsettings/resource_ids.spec`.
