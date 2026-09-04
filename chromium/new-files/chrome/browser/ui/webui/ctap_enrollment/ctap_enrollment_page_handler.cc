// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/ctap_enrollment/ctap_enrollment_page_handler.h"

#include <unistd.h>

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "chrome/browser/webauthn/ctap_client_identity.h"
#include "crypto/hash.h"
#include "crypto/keypair.h"
#include "crypto/random.h"
#include "crypto/sha2.h"
#include "device/bluetooth/bluetooth_adapter_factory.h"
#include "device/bluetooth/bluetooth_discovery_session.h"
#include "device/bluetooth/bluetooth_gatt_connection.h"
#include "device/bluetooth/bluetooth_gatt_notify_session.h"
#include "device/bluetooth/bluetooth_remote_gatt_characteristic.h"
#include "device/bluetooth/bluetooth_remote_gatt_service.h"
#include "device/bluetooth/public/cpp/bluetooth_uuid.h"

namespace {

// The authenticator advertises this service while in enrollment mode and hosts
// a GATT service under it; the client writes its public identity key to the
// characteristic below.
constexpr char kEnrollmentServiceUuid[] =
    "0e310001-70b7-400b-86ba-3d68865ce5cd";
constexpr char kEnrollmentKeyCharUuid[] =
    "0e310002-70b7-400b-86ba-3d68865ce5cd";
// The authenticator notifies this characteristic once the user confirms the
// enrollment on it.
constexpr char kEnrollmentResultCharUuid[] =
    "0e310003-70b7-400b-86ba-3d68865ce5cd";
// The authenticator's stable identifier, read when the connection opens.
constexpr char kEnrollmentAidCharUuid[] =
    "0e310004-70b7-400b-86ba-3d68865ce5cd";
// The authenticator's commitment to its nonce, readable once it has our key.
constexpr char kEnrollmentCommitCharUuid[] =
    "0e310005-70b7-400b-86ba-3d68865ce5cd";
// Our nonce, written after we hold the commitment.
constexpr char kEnrollmentClientNonceCharUuid[] =
    "0e310006-70b7-400b-86ba-3d68865ce5cd";
// The authenticator's nonce, served only once ours is in its hands.
constexpr char kEnrollmentAuthNonceCharUuid[] =
    "0e310007-70b7-400b-86ba-3d68865ce5cd";

constexpr size_t kNonceLength = 16;

// Both sides derive these identically. The commitment fixes the
// authenticator's nonce before we reveal ours; the code then covers both
// public values and both nonces, so no participant can steer it.
std::array<uint8_t, crypto::kSHA256Length> Commitment(
    base::span<const uint8_t> aid,
    base::span<const uint8_t> public_key,
    base::span<const uint8_t> auth_nonce) {
  crypto::hash::Hasher hasher(crypto::hash::HashKind::kSha256);
  hasher.Update(base::as_byte_span(std::string_view("CTAP-enroll-commit")));
  hasher.Update(aid);
  hasher.Update(public_key);
  hasher.Update(auth_nonce);
  std::array<uint8_t, crypto::kSHA256Length> out;
  hasher.Finish(out);
  return out;
}

std::string VerificationCode(base::span<const uint8_t> aid,
                             base::span<const uint8_t> public_key,
                             base::span<const uint8_t> auth_nonce,
                             base::span<const uint8_t> client_nonce) {
  crypto::hash::Hasher hasher(crypto::hash::HashKind::kSha256);
  hasher.Update(base::as_byte_span(std::string_view("CTAP-enroll-code")));
  hasher.Update(aid);
  hasher.Update(public_key);
  hasher.Update(auth_nonce);
  hasher.Update(client_nonce);
  std::array<uint8_t, crypto::kSHA256Length> h;
  hasher.Finish(h);
  const uint32_t v = (static_cast<uint32_t>(h[0]) << 24) |
                     (static_cast<uint32_t>(h[1]) << 16) |
                     (static_cast<uint32_t>(h[2]) << 8) |
                     static_cast<uint32_t>(h[3]);
  return base::StringPrintf("%06u", v % 1000000u);
}

}  // namespace

CtapEnrollmentPageHandler::CtapEnrollmentPageHandler(
    mojo::PendingReceiver<ctap_enrollment::mojom::PageHandler> receiver,
    mojo::PendingRemote<ctap_enrollment::mojom::Page> page,
    Profile* profile)
    : receiver_(this, std::move(receiver)),
      page_(std::move(page)),
      profile_(profile) {}

CtapEnrollmentPageHandler::~CtapEnrollmentPageHandler() {
  if (adapter_) {
    adapter_->RemoveObserver(this);
  }
}

void CtapEnrollmentPageHandler::StartEnrollment() {
  // Reset all state from any previous attempt.
  enrollment_handled_ = false;
  exchange_started_ = false;
  notify_session_.reset();
  gatt_connection_.reset();
  discovery_session_.reset();
  public_key_spki_.clear();
  write_payload_.clear();
  target_address_.clear();
  authenticator_id_.clear();
  client_nonce_.clear();
  commitment_.clear();

  if (!device::BluetoothAdapterFactory::IsBluetoothSupported()) {
    page_->OnScanError("Bluetooth is not supported on this platform.");
    return;
  }
  t_start_ = base::TimeTicks::Now();
  page_->OnStatus("Looking for the authenticator…");
  if (adapter_) {
    // Adapter already obtained and observer already registered; just re-scan.
    StartDiscovery();
    return;
  }
  device::BluetoothAdapterFactory::Get()->GetAdapter(
      base::BindOnce(&CtapEnrollmentPageHandler::OnGetAdapter,
                     weak_factory_.GetWeakPtr()));
}

void CtapEnrollmentPageHandler::OnGetAdapter(
    scoped_refptr<device::BluetoothAdapter> adapter) {
  if (!adapter || !adapter->IsPresent()) {
    page_->OnScanError("No Bluetooth adapter is present.");
    return;
  }
  adapter_ = std::move(adapter);

  if (adapter_->GetOsPermissionStatus() ==
      device::BluetoothAdapter::PermissionStatus::kDenied) {
    page_->OnScanError("Bluetooth permission is denied for this application.");
    return;
  }

  adapter_->AddObserver(this);
  StartDiscovery();
}

void CtapEnrollmentPageHandler::StartDiscovery() {
  adapter_->StartDiscoverySession(
      "ctap-enrollment",
      base::BindOnce(&CtapEnrollmentPageHandler::OnDiscoveryStarted,
                     weak_factory_.GetWeakPtr()),
      base::BindOnce(&CtapEnrollmentPageHandler::OnDiscoveryError,
                     weak_factory_.GetWeakPtr()));
}

void CtapEnrollmentPageHandler::OnDiscoveryStarted(
    std::unique_ptr<device::BluetoothDiscoverySession> session) {
  discovery_session_ = std::move(session);
}

void CtapEnrollmentPageHandler::OnDiscoveryError() {
  page_->OnScanError("Failed to start a Bluetooth scan.");
}

void CtapEnrollmentPageHandler::DeviceAdded(
    device::BluetoothAdapter* adapter,
    device::BluetoothDevice* device) {
  MaybeConnect(device);
}

void CtapEnrollmentPageHandler::DeviceChanged(
    device::BluetoothAdapter* adapter,
    device::BluetoothDevice* device) {
  MaybeConnect(device);
}

void CtapEnrollmentPageHandler::MaybeConnect(device::BluetoothDevice* device) {
  if (enrollment_handled_) {
    return;
  }
  const device::BluetoothUUID enrollment_uuid(kEnrollmentServiceUuid);
  bool advertises_enrollment = false;
  for (const device::BluetoothUUID& uuid : device->GetUUIDs()) {
    if (uuid == enrollment_uuid) {
      advertises_enrollment = true;
      break;
    }
  }
  if (!advertises_enrollment) {
    return;
  }

  enrollment_handled_ = true;
  t_found_ = base::TimeTicks::Now();
  target_address_ = device->GetAddress();
  device_ = device;
  LOG(INFO) << "ctap-enrollment: authenticator found " << target_address_;
  // The identity key can only be chosen once we know which authenticator this
  // is, so it is generated after the identifier is read.
  page_->OnStatus("Connecting to the authenticator…");
  // No service filter: a full discovery populates GetGattServices() reliably.
  device->CreateGattConnection(base::BindOnce(
      &CtapEnrollmentPageHandler::OnGattConnection, weak_factory_.GetWeakPtr()));
}

void CtapEnrollmentPageHandler::OnGattConnection(
    std::unique_ptr<device::BluetoothGattConnection> connection,
    std::optional<device::BluetoothDevice::ConnectErrorCode> error) {
  // We are done scanning now, whatever the outcome.
  discovery_session_.reset();
  if (error.has_value() || !connection) {
    page_->OnScanError("Could not connect to the authenticator.");
    return;
  }
  gatt_connection_ = std::move(connection);
  t_connected_ = base::TimeTicks::Now();
  page_->OnStatus("Connected; sending identity key…");
}

device::BluetoothRemoteGattCharacteristic*
CtapEnrollmentPageHandler::Characteristic(const char* uuid) {
  device::BluetoothDevice* device = device_;
  if (!device) {
    LOG(WARNING) << "ctap-enrollment: no device pointer for " << uuid;
    return nullptr;
  }
  const device::BluetoothUUID service_uuid(kEnrollmentServiceUuid);
  for (device::BluetoothRemoteGattService* s : device->GetGattServices()) {
    if (s->GetUUID() != service_uuid) {
      continue;
    }
    std::vector<device::BluetoothRemoteGattCharacteristic*> chars =
        s->GetCharacteristicsByUUID(device::BluetoothUUID(uuid));
    if (!chars.empty()) {
      return chars[0];
    }
  }
  return nullptr;
}

void CtapEnrollmentPageHandler::GattServicesDiscovered(
    device::BluetoothAdapter* adapter,
    device::BluetoothDevice* device) {
  if (exchange_started_ || device->GetAddress() != target_address_) {
    return;
  }
  device_ = device;
  LOG(INFO) << "ctap-enrollment: services discovered, "
            << device->GetGattServices().size() << " service(s)";
  // This callback can fire before discovery is complete; wait for a later one
  // rather than failing.
  if (!Characteristic(kEnrollmentAidCharUuid)) {
    LOG(WARNING) << "ctap-enrollment: AID characteristic not (yet) present";
    return;
  }
  exchange_started_ = true;
  LOG(INFO) << "ctap-enrollment: exchange started";
  t_services_ = base::TimeTicks::Now();

  // Subscribe to the result characteristic so we learn when the user confirms.
  if (device::BluetoothRemoteGattCharacteristic* result =
          Characteristic(kEnrollmentResultCharUuid)) {
    result->StartNotifySession(
        base::BindOnce(&CtapEnrollmentPageHandler::OnNotifyStarted,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&CtapEnrollmentPageHandler::OnNotifyError,
                       weak_factory_.GetWeakPtr()));
  }
  ReadAid();
}

// Step 1: which authenticator is this?
void CtapEnrollmentPageHandler::ReadAid() {
  device::BluetoothRemoteGattCharacteristic* aid =
      Characteristic(kEnrollmentAidCharUuid);
  if (!aid) {
    page_->OnScanError("The authenticator did not offer an identifier.");
    return;
  }
  aid->ReadRemoteCharacteristic(
      base::BindOnce(&CtapEnrollmentPageHandler::OnAidRead,
                     weak_factory_.GetWeakPtr()));
}

// Step 2: generate this pairing's key and send it.
void CtapEnrollmentPageHandler::OnAidRead(
    std::optional<device::BluetoothGattService::GattErrorCode> error,
    const std::vector<uint8_t>& value) {
  if (error.has_value() || value.empty()) {
    LOG(WARNING) << "ctap-enrollment: " << "Could not read the authenticator's identifier." << " (error=" << (error.has_value() ? static_cast<int>(*error) : -1) << ", " << value.size() << " bytes)";
    page_->OnScanError("Could not read the authenticator's identifier.");
    return;
  }
  authenticator_id_.assign(value.begin(), value.end());
  LOG(INFO) << "ctap-enrollment: AID read (" << value.size() << " bytes)";

  // A distinct key per authenticator: extracting one private key impersonates
  // this client only to the authenticator it was enrolled with.
  crypto::keypair::PrivateKey key =
      ctap_client_identity::GetOrCreateForAuthenticator(profile_,
                                                        authenticator_id_);
  public_key_spki_ = key.ToSubjectPublicKeyInfo();

  device::BluetoothRemoteGattCharacteristic* key_char =
      Characteristic(kEnrollmentKeyCharUuid);
  if (!key_char) {
    page_->OnScanError("The authenticator did not offer a key characteristic.");
    return;
  }

  // A friendly device name plus the public key, both base64 so the small JSON
  // needs no escaping. The name lets the authenticator label the client.
  std::string device_name = "Chromium";
  char hostname[256];
  if (gethostname(hostname, sizeof(hostname)) == 0) {
    device_name = std::string("Chromium on ") + hostname;
  }
  std::string json =
      "{\"name\":\"" + base::Base64Encode(base::as_byte_span(device_name)) +
      "\",\"key\":\"" + base::Base64Encode(public_key_spki_) + "\"}";
  write_payload_.assign(json.begin(), json.end());

  page_->OnStatus("Connected; sending identity key…");
  key_char->WriteRemoteCharacteristic(
      write_payload_,
      device::BluetoothRemoteGattCharacteristic::WriteType::kWithResponse,
      base::BindOnce(&CtapEnrollmentPageHandler::OnKeyWritten,
                     weak_factory_.GetWeakPtr()),
      base::BindOnce(&CtapEnrollmentPageHandler::OnWriteError,
                     weak_factory_.GetWeakPtr()));
}

// Step 3: take the authenticator's commitment before revealing our nonce.
void CtapEnrollmentPageHandler::OnKeyWritten() {
  t_key_written_ = base::TimeTicks::Now();
  LOG(INFO) << "ctap-enrollment: key written";
  device::BluetoothRemoteGattCharacteristic* commit =
      Characteristic(kEnrollmentCommitCharUuid);
  if (!commit) {
    page_->OnScanError("The authenticator did not offer a commitment.");
    return;
  }
  commit->ReadRemoteCharacteristic(
      base::BindOnce(&CtapEnrollmentPageHandler::OnCommitmentRead,
                     weak_factory_.GetWeakPtr()));
}

// Step 4: our nonce, chosen without knowledge of theirs.
void CtapEnrollmentPageHandler::OnCommitmentRead(
    std::optional<device::BluetoothGattService::GattErrorCode> error,
    const std::vector<uint8_t>& value) {
  if (error.has_value() || value.size() != crypto::kSHA256Length) {
    LOG(WARNING) << "ctap-enrollment: " << "The authenticator did not commit to its nonce." << " (error=" << (error.has_value() ? static_cast<int>(*error) : -1) << ", " << value.size() << " bytes)";
    page_->OnScanError("The authenticator did not commit to its nonce.");
    return;
  }
  commitment_.assign(value.begin(), value.end());
  LOG(INFO) << "ctap-enrollment: commitment read";

  client_nonce_.resize(kNonceLength);
  crypto::RandBytes(client_nonce_);

  device::BluetoothRemoteGattCharacteristic* nonce_char =
      Characteristic(kEnrollmentClientNonceCharUuid);
  if (!nonce_char) {
    page_->OnScanError("The authenticator did not offer a nonce characteristic.");
    return;
  }
  nonce_char->WriteRemoteCharacteristic(
      client_nonce_,
      device::BluetoothRemoteGattCharacteristic::WriteType::kWithResponse,
      base::BindOnce(&CtapEnrollmentPageHandler::OnClientNonceWritten,
                     weak_factory_.GetWeakPtr()),
      base::BindOnce(&CtapEnrollmentPageHandler::OnWriteError,
                     weak_factory_.GetWeakPtr()));
}

// Step 5: now they may open their commitment.
void CtapEnrollmentPageHandler::OnClientNonceWritten() {
  LOG(INFO) << "ctap-enrollment: client nonce written";
  device::BluetoothRemoteGattCharacteristic* auth_nonce =
      Characteristic(kEnrollmentAuthNonceCharUuid);
  if (!auth_nonce) {
    page_->OnScanError("The authenticator did not offer its nonce.");
    return;
  }
  auth_nonce->ReadRemoteCharacteristic(
      base::BindOnce(&CtapEnrollmentPageHandler::OnAuthNonceRead,
                     weak_factory_.GetWeakPtr()));
}

// Step 6: check the commitment, then show the code.
void CtapEnrollmentPageHandler::OnAuthNonceRead(
    std::optional<device::BluetoothGattService::GattErrorCode> error,
    const std::vector<uint8_t>& value) {
  if (error.has_value() || value.size() != kNonceLength) {
    LOG(WARNING) << "ctap-enrollment: " << "The authenticator did not reveal its nonce." << " (error=" << (error.has_value() ? static_cast<int>(*error) : -1) << ", " << value.size() << " bytes)";
    page_->OnScanError("The authenticator did not reveal its nonce.");
    return;
  }
  const std::array<uint8_t, crypto::kSHA256Length> expected =
      Commitment(authenticator_id_, public_key_spki_, value);
  if (!std::ranges::equal(expected, commitment_)) {
    // The nonce does not open the commitment we were given, so it was chosen
    // after ours: refuse rather than display a code the peer could have steered.
    page_->OnScanError(
        "The authenticator's nonce does not match its commitment; enrollment "
        "aborted.");
    return;
  }
  const base::TimeTicks t_code = base::TimeTicks::Now();
  // MEASURE enrollment: wall-clock from scan start to code displayed, and the
  // committed numeric-comparison exchange alone (4 GATT ops after the key write).
  LOG(INFO) << "MEASURE enrollment discover_ms="
            << (t_found_ - t_start_).InMilliseconds()
            << " connect_ms=" << (t_connected_ - t_found_).InMilliseconds()
            << " services_ms=" << (t_services_ - t_connected_).InMilliseconds()
            << " aid_key_ms=" << (t_key_written_ - t_services_).InMilliseconds()
            << " comparison_ms=" << (t_code - t_key_written_).InMilliseconds()
            << " total_ms=" << (t_code - t_start_).InMilliseconds()
            << " gatt_ops=6";
  page_->OnVerificationCode(VerificationCode(authenticator_id_,
                                             public_key_spki_, value,
                                             client_nonce_));
  page_->OnStatus("Identity key sent. Type this code on your authenticator.");
}

void CtapEnrollmentPageHandler::GattCharacteristicValueChanged(
    device::BluetoothAdapter* adapter,
    device::BluetoothRemoteGattCharacteristic* characteristic,
    const std::vector<uint8_t>& value) {
  if (characteristic->GetUUID() ==
      device::BluetoothUUID(kEnrollmentResultCharUuid)) {
    page_->OnEnrolled();
  }
}

void CtapEnrollmentPageHandler::OnNotifyStarted(
    std::unique_ptr<device::BluetoothGattNotifySession> session) {
  notify_session_ = std::move(session);
}

void CtapEnrollmentPageHandler::OnNotifyError(
    device::BluetoothGattService::GattErrorCode error) {
  // Non-fatal: the key is still delivered; we just won't get the confirmation
  // push. Leave the "confirm on your authenticator" status in place.
}

void CtapEnrollmentPageHandler::OnWriteError(
    device::BluetoothGattService::GattErrorCode error) {
  LOG(WARNING) << "ctap-enrollment: GATT write failed, code "
               << static_cast<int>(error);
  page_->OnScanError("The enrollment exchange with the authenticator failed.");
}
