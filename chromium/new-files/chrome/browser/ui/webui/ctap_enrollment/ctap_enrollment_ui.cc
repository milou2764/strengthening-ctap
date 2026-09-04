// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/ctap_enrollment/ctap_enrollment_ui.h"

#include <memory>
#include <utility>

#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/webui/ctap_enrollment/ctap_enrollment_page_handler.h"
#include "chrome/common/webui_url_constants.h"
#include "chrome/grit/ctap_enrollment_resources.h"
#include "chrome/grit/ctap_enrollment_resources_map.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_data_source.h"
#include "content/public/common/url_constants.h"
#include "ui/webui/webui_util.h"

CtapEnrollmentUIConfig::CtapEnrollmentUIConfig()
    : DefaultWebUIConfig(content::kChromeUIScheme,
                         chrome::kChromeUICtapEnrollmentHost) {}

CtapEnrollmentUI::CtapEnrollmentUI(content::WebUI* web_ui)
    : ui::MojoWebUIController(web_ui) {
  content::WebUIDataSource* source = content::WebUIDataSource::CreateAndAdd(
      Profile::FromWebUI(web_ui), chrome::kChromeUICtapEnrollmentHost);
  webui::SetupWebUIDataSource(source, kCtapEnrollmentResources,
                              IDR_CTAP_ENROLLMENT_INDEX_HTML);
}

CtapEnrollmentUI::~CtapEnrollmentUI() = default;

void CtapEnrollmentUI::BindInterface(
    mojo::PendingReceiver<ctap_enrollment::mojom::PageHandlerFactory>
        receiver) {
  factory_receiver_.reset();
  factory_receiver_.Bind(std::move(receiver));
}

void CtapEnrollmentUI::CreatePageHandler(
    mojo::PendingRemote<ctap_enrollment::mojom::Page> page,
    mojo::PendingReceiver<ctap_enrollment::mojom::PageHandler> receiver) {
  page_handler_ = std::make_unique<CtapEnrollmentPageHandler>(
      std::move(receiver), std::move(page), Profile::FromWebUI(web_ui()));
}

WEB_UI_CONTROLLER_TYPE_IMPL(CtapEnrollmentUI)
