/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.webwolf.jwt.JWTController;
import org.owasp.webgoat.webwolf.mailbox.MailboxController;
import org.owasp.webgoat.webwolf.mailbox.MailboxRepository;
import org.owasp.webgoat.webwolf.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest({JWTController.class, MailboxController.class, CsrfTokenController.class})
@Import({WebSecurityConfig.class, MvcConfiguration.class})
@WithMockUser
class CsrfProtectionTest {

  @Autowired private MockMvc mvc;
  @MockBean private ClientRegistrationRepository clientRegistrationRepository;
  @MockBean private UserService userService;
  @MockBean private MailboxRepository mailboxRepository;

  @Test
  void authenticatedPostWithoutCsrfTokenIsRejected() throws Exception {
    mvc.perform(
            post("/jwt/decode")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content("token=invalid&secretKey=invalid"))
        .andExpect(status().isForbidden());
  }

  @Test
  void headerlessApiLoginCanBootstrapSessionWithoutCsrfToken() throws Exception {
    mvc.perform(
            post("/login")
                .with(anonymous())
                .param("username", "invalid")
                .param("password", "invalid"))
        .andExpect(status().isFound());
  }

  @Test
  void browserOriginatedLoginWithoutCsrfTokenIsRejected() throws Exception {
    mvc.perform(
            post("/login")
                .with(anonymous())
                .header("Origin", "https://attacker.example")
                .param("username", "invalid")
                .param("password", "invalid"))
        .andExpect(status().isForbidden());
  }

  @Test
  void loginFormContainsCsrfToken() throws Exception {
    mvc.perform(get("/login").with(anonymous()))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("name=\"_csrf\"")));
  }

  @Test
  void apiTokenCookieAndHeaderAuthorizeSameOriginPost() throws Exception {
    var tokenResponse =
        mvc.perform(get("/csrf/token").with(anonymous()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
            .andExpect(jsonPath("$.parameterName").value("_csrf"))
            .andExpect(cookie().exists("XSRF-TOKEN"))
            .andReturn();
    String token = JsonPath.read(tokenResponse.getResponse().getContentAsString(), "$.token");
    var tokenCookie = tokenResponse.getResponse().getCookie("XSRF-TOKEN");
    assertThat(tokenCookie.getAttribute("SameSite")).isEqualTo("Strict");
    assertThat(tokenCookie.isHttpOnly()).isFalse();

    mvc.perform(
            post("/jwt/decode")
                .cookie(tokenCookie)
                .header("X-XSRF-TOKEN", token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content("token=invalid&secretKey=invalid"))
        .andExpect(status().isOk());
  }

  @Test
  void unauthenticatedInboundMailReceiverDoesNotRequireSessionCsrfToken() throws Exception {
    mvc.perform(
            post("/mail")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"recipient":"alice","sender":"sender","title":"subject","contents":"body"}
                    """))
        .andExpect(status().isCreated());
  }
}
