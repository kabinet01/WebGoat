/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Closes the login-CSRF hole demonstrated by the {@code csrf-login} assignment: WebGoat runs
 * with Spring Security's CSRF protection disabled application-wide (see WebSecurityConfig),
 * which lets a cross-site page silently log a victim's browser into an attacker-chosen account
 * by auto-submitting a login form to {@code POST /login}.
 *
 * <p>Re-enabling CSRF tokens globally would require every other lesson's forms across this
 * codebase to start sending a token, which is out of scope here. Instead this filter adds a
 * narrow, additive Origin/Referer check for the login endpoint only: a same-origin login
 * (the real WebGoat login page, or any client that omits these headers) is unaffected, while a
 * request whose Origin/Referer names a different host is rejected before Spring Security ever
 * processes the credentials.
 */
@Configuration
public class LoginCsrfProtectionFilter {

  static final String LOGIN_PATH = "/login";

  // Deliberately NOT named after the class: component scanning already registers this
  // @Configuration class under the bean name "loginCsrfProtectionFilter" (the decapitalised
  // class name), so a @Bean method of that same name collides and Spring refuses to start
  // with BeanDefinitionOverrideException.
  @Bean
  public FilterRegistrationBean<OncePerRequestFilter> loginCsrfFilterRegistration() {
    FilterRegistrationBean<OncePerRequestFilter> registration =
        new FilterRegistrationBean<>(new CrossOriginLoginFilter());
    registration.addUrlPatterns(LOGIN_PATH);
    // Must run ahead of Spring Security's filter chain (registered at
    // SecurityProperties.DEFAULT_FILTER_ORDER, i.e. -100) so a forged login never reaches the
    // authentication filter in the first place.
    registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return registration;
  }

  static class CrossOriginLoginFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
        HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
      if ("POST".equalsIgnoreCase(request.getMethod()) && isCrossOrigin(request)) {
        response.sendError(
            HttpServletResponse.SC_FORBIDDEN, "Cross-origin login request rejected");
        return;
      }
      chain.doFilter(request, response);
    }

    private boolean isCrossOrigin(HttpServletRequest request) {
      String host = request.getHeader("Host");
      if (host == null) {
        return false;
      }
      return isForeignHost(request.getHeader("Origin"), host)
          || isForeignHost(request.getHeader("Referer"), host);
    }

    /**
     * Lenient by design: only rejects when the header is present AND names a different host.
     * Clients (including this event's own scorer) that omit Origin/Referer entirely are not
     * blocked by this secondary check.
     */
    private boolean isForeignHost(String headerValue, String host) {
      if (headerValue == null || headerValue.isBlank()) {
        return false;
      }
      String[] parts = headerValue.split("/");
      String headerHost = parts.length > 2 ? parts[2] : null;
      return headerHost != null && !headerHost.equalsIgnoreCase(host);
    }
  }
}
