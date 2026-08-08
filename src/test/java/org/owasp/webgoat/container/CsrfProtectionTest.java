/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class CsrfProtectionTest extends LessonTest {

  @BeforeEach
  void setupSecurity() {
    this.mockMvc =
        MockMvcBuilders.webAppContextSetup(this.wac).apply(springSecurity()).build();
  }

  @Test
  void authenticatedPostWithoutCsrfTokenIsRejected() throws Exception {
    mockMvc.perform(post("/JWT/refresh/checkout")).andExpect(status().isForbidden());
  }

  @Test
  void headerlessApiLoginCanBootstrapSessionWithoutCsrfToken() throws Exception {
    mockMvc
        .perform(
            post("/login")
                .with(anonymous())
                .param("username", "invalid")
                .param("password", "invalid"))
        .andExpect(status().isFound());
  }

  @Test
  void headerlessApiRegistrationCanBootstrapSessionWithoutCsrfToken() throws Exception {
    mockMvc
        .perform(
            post("/register.mvc")
                .with(anonymous())
                .param("username", "x")
                .param("password", "x")
                .param("matchingPassword", "x")
                .param("agree", "agree"))
        .andExpect(status().isOk());
  }

  @Test
  void browserOriginatedLoginWithoutCsrfTokenIsRejected() throws Exception {
    mockMvc
        .perform(
            post("/login")
                .with(anonymous())
                .header("Origin", "https://attacker.example")
                .param("username", "invalid")
                .param("password", "invalid"))
        .andExpect(status().isForbidden());
  }

  @Test
  void loginFormContainsCsrfToken() throws Exception {
    mockMvc
        .perform(get("/login").with(anonymous()))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("name=\"_csrf\"")));
  }

  @Test
  void apiTokenCookieAndHeaderAuthorizeSameOriginPost() throws Exception {
    var tokenResponse =
        mockMvc
            .perform(get("/csrf/token").with(anonymous()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
            .andExpect(jsonPath("$.parameterName").value("_csrf"))
            .andExpect(cookie().exists("XSRF-TOKEN"))
            .andReturn();
    String token = JsonPath.read(tokenResponse.getResponse().getContentAsString(), "$.token");
    var tokenCookie = tokenResponse.getResponse().getCookie("XSRF-TOKEN");
    assertThat(tokenCookie.getAttribute("SameSite")).isEqualTo("Strict");
    assertThat(tokenCookie.isHttpOnly()).isFalse();

    mockMvc
        .perform(
            post("/JWT/refresh/checkout")
                .cookie(tokenCookie)
                .header("X-XSRF-TOKEN", token))
        .andExpect(status().isUnauthorized());
  }
}
