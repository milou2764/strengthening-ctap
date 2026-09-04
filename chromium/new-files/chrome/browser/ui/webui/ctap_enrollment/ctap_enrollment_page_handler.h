// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_CTAP_ENROLLMENT_CTAP_ENROLLMENT_PAGE_HANDLER_H_
#define CHROME_BROWSER_UI_WEBUI_CTAP_ENROLLMENT_CTAP_ENROLLMENT_PAGE_HANDLER_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "chrome/browser/ui/webui/ctap_enrollment/ctap_enrollment.mojom.h"
#include "device/bluetooth/bluetooth_adapter.h"
#include "device/bluetooth/bluetooth_device.h"
#include "device/bluetooth/bluetooth_gatt_service.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"

class Profile;

namespace device {
class BluetoothDiscoverySession;
class BluetoothGattConnection;
class BluetoothGattNotifySession;
class BluetoothRemoteGattCharacteristic;
}  // namespace device

// Browser-side implementation of the chrome://ctap-enrollment Mojo interface.
// Acts as a BLE central: it finds the authenticator (which advertises the
// enrollment service UUID), opens a direct GATT connection, and runs the
// enrollment exchange. It reads the authenticator identifier, writes a public
// identity key generated for that authenticator alone, and then runs the
// committed numeric comparison: the authenticator commits to its nonce, this
// side reveals its own, the authenticator opens its commitment, and both derive
// the six-digit code from the two public values and the two nonces. Because
// each nonce is fixed before the other is known, neither side -- nor an
// adversary running a second pairing -- can steer the code the user compares.
class CtapEnrollmentPageHandler : public ctap_enrollment::mojom::PageHandler,
                                  public device::BluetoothAdapter::Observer {
 public:
  CtapEnrollmentPageHandler(
      mojo::PendingReceiver<ctap_enrollment::mojom::PageHandler> receiver,
      mojo::PendingRemote<ctap_enrollment::mojom::Page> page,
      Profile* profile);
  CtapEnrollmentPageHandler(const CtapEnrollmentPageHandler&) = delete;
  CtapEnrollmentPageHandler& operator=(const CtapEnrollmentPageHandler&) =
      delete;
  ~CtapEnrollmentPageHandler() override;

  // ctap_enrollment::mojom::PageHandler:
  void StartEnrollment() override;

  // device::BluetoothAdapter::Observer:
  void DeviceAdded(device::BluetoothAdapter* adapter,
                   device::BluetoothDevice* device) override;
  void DeviceChanged(device::BluetoothAdapter* adapter,
                     device::BluetoothDevice* device) override;
  void GattServicesDiscovered(device::BluetoothAdapter* adapter,
                              device::BluetoothDevice* device) override;
  void GattCharacteristicValueChanged(
      device::BluetoothAdapter* adapter,
      device::BluetoothRemoteGattCharacteristic* characteristic,
      const std::vector<uint8_t>& value) override;

 private:
  void OnGetAdapter(scoped_refptr<device::BluetoothAdapter> adapter);
  void StartDiscovery();
  void OnDiscoveryStarted(
      std::unique_ptr<device::BluetoothDiscoverySession> session);
  void OnDiscoveryError();
  // Connects if `device` advertises the enrollment service. Uses the device
  // pointer directly (DeviceAdded/DeviceChanged fire after the device is in the
  // adapter's map, unlike DeviceAdvertisementReceived).
  void MaybeConnect(device::BluetoothDevice* device);
  void OnGattConnection(
      std::unique_ptr<device::BluetoothGattConnection> connection,
      std::optional<device::BluetoothDevice::ConnectErrorCode> error);
  // The enrollment exchange, in order.
  void ReadAid();
  void OnAidRead(std::optional<device::BluetoothGattService::GattErrorCode> error,
                 const std::vector<uint8_t>& value);
  void OnKeyWritten();
  void OnCommitmentRead(
      std::optional<device::BluetoothGattService::GattErrorCode> error,
      const std::vector<uint8_t>& value);
  void OnClientNonceWritten();
  void OnAuthNonceRead(
      std::optional<device::BluetoothGattService::GattErrorCode> error,
      const std::vector<uint8_t>& value);
  void OnWriteError(device::BluetoothGattService::GattErrorCode error);
  // Returns the characteristic with `uuid` on the enrollment service, or null.
  device::BluetoothRemoteGattCharacteristic* Characteristic(const char* uuid);
  void OnNotifyStarted(
      std::unique_ptr<device::BluetoothGattNotifySession> session);
  void OnNotifyError(device::BluetoothGattService::GattErrorCode error);

  mojo::Receiver<ctap_enrollment::mojom::PageHandler> receiver_;
  mojo::Remote<ctap_enrollment::mojom::Page> page_;
  raw_ptr<Profile> profile_;
  scoped_refptr<device::BluetoothAdapter> adapter_;
  std::unique_ptr<device::BluetoothDiscoverySession> discovery_session_;
  std::unique_ptr<device::BluetoothGattConnection> gatt_connection_;
  std::unique_ptr<device::BluetoothGattNotifySession> notify_session_;
  std::string target_address_;
  // The authenticator, as handed to us by the adapter callbacks. Looked up by
  // address on macOS this can come back null, so it is kept here instead.
  raw_ptr<device::BluetoothDevice> device_ = nullptr;
  std::vector<uint8_t> public_key_spki_;
  std::vector<uint8_t> write_payload_;
  std::vector<uint8_t> authenticator_id_;
  std::vector<uint8_t> client_nonce_;
  std::vector<uint8_t> commitment_;
  bool enrollment_handled_ = false;
  // Measurement: enrollment timeline (scan start, GATT connected, code shown).
  base::TimeTicks t_start_;
  base::TimeTicks t_found_;
  base::TimeTicks t_connected_;
  base::TimeTicks t_services_;
  base::TimeTicks t_key_written_;
  bool exchange_started_ = false;

  base::WeakPtrFactory<CtapEnrollmentPageHandler> weak_factory_{this};
};

#endif  // CHROME_BROWSER_UI_WEBUI_CTAP_ENROLLMENT_CTAP_ENROLLMENT_PAGE_HANDLER_H_
