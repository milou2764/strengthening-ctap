// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_CTAP_ENROLLMENT_CTAP_ENROLLMENT_UI_H_
#define CHROME_BROWSER_UI_WEBUI_CTAP_ENROLLMENT_CTAP_ENROLLMENT_UI_H_

#include <memory>

#include "chrome/browser/ui/webui/ctap_enrollment/ctap_enrollment.mojom.h"
#include "content/public/browser/webui_config.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "ui/webui/mojo_web_ui_controller.h"

namespace content {
class WebUI;
}  // namespace content

class CtapEnrollmentUI;

class CtapEnrollmentUIConfig
    : public content::DefaultWebUIConfig<CtapEnrollmentUI> {
 public:
  CtapEnrollmentUIConfig();
};

// WebUI for chrome://ctap-enrollment. Enrolls this client with a CTAP
// authenticator: it reads the authenticator's BLE enrollment nonce, holds a
// client identity key, signs the nonce (proof of possession), and displays a
// QR code that the authenticator scans to store the client's public key.
class CtapEnrollmentUI : public ui::MojoWebUIController,
                         public ctap_enrollment::mojom::PageHandlerFactory {
 public:
  explicit CtapEnrollmentUI(content::WebUI* web_ui);
  CtapEnrollmentUI(const CtapEnrollmentUI&) = delete;
  CtapEnrollmentUI& operator=(const CtapEnrollmentUI&) = delete;
  ~CtapEnrollmentUI() override;

  // Binds the PageHandlerFactory receiver for this page. Called by the WebUI
  // interface binder.
  void BindInterface(
      mojo::PendingReceiver<ctap_enrollment::mojom::PageHandlerFactory>
          receiver);

 private:
  // ctap_enrollment::mojom::PageHandlerFactory:
  void CreatePageHandler(
      mojo::PendingRemote<ctap_enrollment::mojom::Page> page,
      mojo::PendingReceiver<ctap_enrollment::mojom::PageHandler> receiver)
      override;

  std::unique_ptr<ctap_enrollment::mojom::PageHandler> page_handler_;
  mojo::Receiver<ctap_enrollment::mojom::PageHandlerFactory> factory_receiver_{
      this};

  WEB_UI_CONTROLLER_TYPE_DECL();
};

#endif  // CHROME_BROWSER_UI_WEBUI_CTAP_ENROLLMENT_CTAP_ENROLLMENT_UI_H_
