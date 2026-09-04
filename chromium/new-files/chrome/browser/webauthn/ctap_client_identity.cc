// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/webauthn/ctap_client_identity.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "chrome/browser/profiles/profile.h"
#include "base/no_destructor.h"
#include "chrome/browser/browser_process.h"
#include "components/os_crypt/async/browser/os_crypt_async.h"
#include "components/os_crypt/async/common/encryptor.h"
#include "components/pref_registry/pref_registry_syncable.h"
#include "components/prefs/pref_service.h"
#include "components/prefs/scoped_user_pref_update.h"

namespace ctap_client_identity {

namespace {

// Maps hex(AID) -> base64(OS-encrypted PKCS#8 PrivateKeyInfo). One key per
// enrolled authenticator; the private keys are wrapped with the platform's
// protected storage rather than left readable in the profile.
constexpr char kClientIdentityKeysPref[] = "webauthn.ctap_client_identity_keys";

// The platform's protected key store, reached through OSCryptAsync (the
// macOS Keychain, DPAPI on Windows, the Freedesktop secret service on Linux).
// The instance is vended asynchronously but is normally ready by the time a
// key is needed; it is cached here and used synchronously afterwards.
scoped_refptr<os_crypt_async::Encryptor>& CachedEncryptor() {
  static base::NoDestructor<scoped_refptr<os_crypt_async::Encryptor>> encryptor;
  return *encryptor;
}

os_crypt_async::Encryptor* GetEncryptor() {
  if (!CachedEncryptor() && g_browser_process &&
      g_browser_process->os_crypt_async()) {
    // Runs synchronously when the instance is already available, which is the
    // usual case outside of early startup.
    g_browser_process->os_crypt_async()->GetInstance(base::BindOnce(
        [](scoped_refptr<os_crypt_async::Encryptor> instance) {
          CachedEncryptor() = std::move(instance);
        }));
  }
  return CachedEncryptor().get();
}

// Wraps `der` for storage. Falls back to plaintext when the platform's
// protected storage is unavailable, which happens on some development builds;
// the entry is then no worse than the profile it lives in.
std::string Wrap(base::span<const uint8_t> der) {
  const std::string plain(reinterpret_cast<const char*>(der.data()),
                          der.size());
  std::string wrapped;
  os_crypt_async::Encryptor* encryptor = GetEncryptor();
  if (encryptor && encryptor->EncryptString(plain, &wrapped)) {
    return base::Base64Encode(wrapped) + ":1";
  }
  LOG(WARNING) << "ctap_client_identity: protected storage unavailable; "
                  "storing the identity key unwrapped";
  return base::Base64Encode(plain) + ":0";
}

std::optional<crypto::keypair::PrivateKey> Unwrap(const std::string& stored) {
  const size_t sep = stored.rfind(':');
  if (sep == std::string::npos) {
    return std::nullopt;
  }
  const std::string body = stored.substr(0, sep);
  const bool encrypted = stored.substr(sep + 1) == "1";

  std::optional<std::vector<uint8_t>> raw = base::Base64Decode(body);
  if (!raw) {
    return std::nullopt;
  }
  std::string der(reinterpret_cast<const char*>(raw->data()), raw->size());
  if (encrypted) {
    os_crypt_async::Encryptor* encryptor = GetEncryptor();
    std::string plain;
    if (!encryptor || !encryptor->DecryptString(der, &plain)) {
      return std::nullopt;
    }
    der = std::move(plain);
  }
  std::optional<crypto::keypair::PrivateKey> key =
      crypto::keypair::PrivateKey::FromPrivateKeyInfo(
          base::as_byte_span(der));
  if (!key || !key->IsEcP256()) {
    return std::nullopt;
  }
  return key;
}

}  // namespace

void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry) {
  registry->RegisterDictionaryPref(kClientIdentityKeysPref);
}

std::string AidToKey(base::span<const uint8_t> aid) {
  return base::ToLowerASCII(base::HexEncode(aid));
}

crypto::keypair::PrivateKey GetOrCreateForAuthenticator(
    Profile* profile,
    base::span<const uint8_t> aid) {
  PrefService* prefs = profile->GetPrefs();
  const std::string index = AidToKey(aid);

  const base::DictValue& keys = prefs->GetDict(kClientIdentityKeysPref);
  if (const std::string* stored = keys.FindString(index)) {
    std::optional<crypto::keypair::PrivateKey> key = Unwrap(*stored);
    if (key) {
      return std::move(*key);
    }
  }

  // No key for this authenticator yet: this enrollment gets its own.
  crypto::keypair::PrivateKey key =
      crypto::keypair::PrivateKey::GenerateEcP256();
  ScopedDictPrefUpdate update(prefs, kClientIdentityKeysPref);
  update->Set(index, Wrap(key.ToPrivateKeyInfo()));
  return key;
}

KeyMap GetAll(Profile* profile) {
  KeyMap out;
  const base::DictValue& keys =
      profile->GetPrefs()->GetDict(kClientIdentityKeysPref);
  for (const auto [index, value] : keys) {
    const std::string* stored = value.GetIfString();
    if (!stored) {
      continue;
    }
    std::optional<crypto::keypair::PrivateKey> key = Unwrap(*stored);
    if (key) {
      out.emplace(index, std::move(*key));
    }
  }
  return out;
}

}  // namespace ctap_client_identity
