/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Token discovery endpoint for non-browser API clients. */
@RestController
public class CsrfTokenController {

  @GetMapping("/csrf/token")
  public CsrfTokenResponse token(CsrfToken csrfToken) {
    return new CsrfTokenResponse(
        csrfToken.getHeaderName(), csrfToken.getParameterName(), csrfToken.getToken());
  }

  record CsrfTokenResponse(String headerName, String parameterName, String token) {}
}
