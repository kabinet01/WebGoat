/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import org.springframework.security.web.util.matcher.RequestMatcher;

/** CSRF request matchers shared by WebGoat's browser and API authentication entry points. */
public final class CsrfRequestMatchers {

  private CsrfRequestMatchers() {}

  /**
   * Allows non-browser API clients to bootstrap a session without a CSRF token. Browsers attach
   * Origin or Referer to form POSTs, so their authentication requests remain protected by the
   * framework token check. Headerless clients cannot implicitly attach another user's cookies.
   */
  public static RequestMatcher tokenlessApiAuthentication(String... servletPaths) {
    Set<String> paths = Set.of(servletPaths);
    return request ->
        "POST".equalsIgnoreCase(request.getMethod())
            && paths.contains(applicationPath(request))
            && request.getHeader("Origin") == null
            && request.getHeader("Referer") == null;
  }

  private static String applicationPath(HttpServletRequest request) {
    String requestUri = request.getRequestURI();
    String contextPath = request.getContextPath();
    return contextPath.isEmpty() ? requestUri : requestUri.substring(contextPath.length());
  }
}
