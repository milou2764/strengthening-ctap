// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {CrLitElement} from 'chrome://resources/lit/v3_0/lit.rollup.js';

import {getHtml} from './app.html.js';
import {PageCallbackRouter, PageHandlerFactory, PageHandlerRemote} from './ctap_enrollment.mojom-webui.js';

export class CtapEnrollmentAppElement extends CrLitElement {
  static get is() {
    return 'ctap-enrollment-app';
  }

  override render() {
    return getHtml.bind(this)();
  }

  static override get properties() {
    return {
      status_: {type: String},
      code_: {type: String},
      error_: {type: String},
      running_: {type: Boolean},
    };
  }

  protected accessor status_: string = '';
  protected accessor code_: string = '';
  protected accessor error_: string = '';
  protected accessor running_: boolean = false;

  private handler_: PageHandlerRemote = new PageHandlerRemote();
  private callbackRouter_: PageCallbackRouter = new PageCallbackRouter();

  constructor() {
    super();
    PageHandlerFactory.getRemote().createPageHandler(
        this.callbackRouter_.$.bindNewPipeAndPassRemote(),
        this.handler_.$.bindNewPipeAndPassReceiver());
    this.callbackRouter_.onStatus.addListener(
        (message: string) => this.onStatus_(message));
    this.callbackRouter_.onVerificationCode.addListener(
        (code: string) => this.onVerificationCode_(code));
    this.callbackRouter_.onEnrolled.addListener(() => this.onEnrolled_());
    this.callbackRouter_.onScanError.addListener(
        (message: string) => this.onScanError_(message));
  }

  protected onStartClick_() {
    this.error_ = '';
    this.code_ = '';
    this.status_ = '';
    this.running_ = true;
    this.handler_.startEnrollment();
  }

  private onStatus_(message: string) {
    this.status_ = message;
  }

  private onVerificationCode_(code: string) {
    this.code_ = code;
    this.running_ = false;
  }

  private onEnrolled_() {
    this.code_ = '';
    this.status_ = 'Enrolled. This client is now trusted by your authenticator.';
  }

  private onScanError_(message: string) {
    this.error_ = message;
    this.running_ = false;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'ctap-enrollment-app': CtapEnrollmentAppElement;
  }
}

customElements.define(CtapEnrollmentAppElement.is, CtapEnrollmentAppElement);
