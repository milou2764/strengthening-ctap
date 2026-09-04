// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {html} from '//resources/lit/v3_0/lit.rollup.js';

import type {CtapEnrollmentAppElement} from './app.ts';

export function getHtml(this: CtapEnrollmentAppElement) {
  return html`
<h1>CTAP client enrollment</h1>
<p>Enroll this client with your authenticator. On the authenticator, choose to
enroll a new client, then click below.</p>
<button @click="${this.onStartClick_}">Enroll this client</button>
${this.status_ ? html`<p>${this.status_}</p>` : ''}
${this.error_ ? html`<p style="color: red">${this.error_}</p>` : ''}
${this.code_ ? html`
  <p><strong>Verification code</strong> &mdash; confirm it matches the one shown
    on your authenticator:</p>
  <p style="font-size: 2.5em; font-family: monospace">${this.code_}</p>` : ''}`;
}
