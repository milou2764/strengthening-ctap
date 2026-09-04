// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_WEBAUTHN_CTAP_CLIENT_IDENTITY_H_
#define CHROME_BROWSER_WEBAUTHN_CTAP_CLIENT_IDENTITY_H_

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "base/containers/span.h"
#include "crypto/keypair.h"

class Profile;

namespace user_prefs {
class PrefRegistrySyncable;
}  // namespace user_prefs

namespace ctap_client_identity {

// Enrolled client identity keys, indexed by the lower-case hex encoding of the
// authenticator identifier (AID) they were enrolled with.
using KeyMap = std::map<std::string, crypto::keypair::PrivateKey>;

// Registers the per-profile CTAP client identity preference.
void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry);

// Returns the key this profile enrolled with the authenticator `aid`,
// generating and storing a fresh one if there is none. The client keeps a
// distinct key per authenticator, so that extracting one private key
// impersonates the client only to the one authenticator it was enrolled with,
// and revocation stays local to that pairing.
crypto::keypair::PrivateKey GetOrCreateForAuthenticator(
    Profile* profile,
    base::span<const uint8_t> aid);

// Returns every enrolled key. The client learns which authenticator it is
// talking to only once the hybrid session is up, so the whole set is carried
// down to the transport, which selects by AID.
KeyMap GetAll(Profile* profile);

// Lower-case hex, the form used to index KeyMap.
std::string AidToKey(base::span<const uint8_t> aid);

}  // namespace ctap_client_identity

#endif  // CHROME_BROWSER_WEBAUTHN_CTAP_CLIENT_IDENTITY_H_
