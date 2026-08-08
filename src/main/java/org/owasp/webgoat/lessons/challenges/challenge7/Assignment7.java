/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 4/8/17.
 */
@RestController
@Slf4j
public class Assignment7 implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  // Maps a securely-random, single-use reset token to the account it was issued for. Reset
  // links used to be predictable (a fixed seed for "admin") or even a hardcoded constant, so
  // anyone could compute or simply read the admin's reset link without ever requesting it or
  // reading the admin's mailbox. Tokens are now unpredictable, bound to the account they were
  // generated for, and consumed (removed) the moment they are used.
  private final Map<String, String> pendingResetLinks = new ConcurrentHashMap<>();

  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='%s:8080/WebGoat/challenge/7/reset-password/%s'>link</a> to reset your"
          + " password.\n"
          + " \n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "If you have any comments or questions, please do not hesitate to reach us at"
          + " support@webgoat-cloud.org\n\n"
          + "Kind regards, \n"
          + "Team WebGoat";

  private final Flags flags;
  private final RestTemplate restTemplate;
  private final String webWolfMailURL;

  public Assignment7(
      Flags flags, RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.flags = flags;
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link) {
    // Single use: the token is removed as soon as it is redeemed, valid or not.
    String username = pendingResetLinks.remove(link);
    if ("admin".equalsIgnoreCase(username)) {
      return ResponseEntity.accepted()
          .body(
              "<h1>Success!!</h1>"
                  + "<img src='/WebGoat/images/hi-five-cat.jpg'>"
                  + "<br/><br/>Here is your flag: "
                  + flags.getFlag(7));
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not the reset link for admin");
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email, HttpServletRequest request)
      throws URISyntaxException {
    if (StringUtils.hasText(email)) {
      String username = email.substring(0, email.indexOf("@"));
      if (StringUtils.hasText(username)) {
        URI uri = new URI(request.getRequestURL().toString());
        String resetLink = generateSecureResetToken();
        pendingResetLinks.put(resetLink, username);
        Email mail =
            Email.builder()
                .title("Your password reset link for challenge 7")
                .contents(
                    String.format(
                        TEMPLATE, uri.getScheme() + "://" + uri.getHost(), resetLink))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .time(LocalDateTime.now())
                .build();
        restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
      }
    }
    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private static String generateSecureResetToken() {
    byte[] randomBytes = new byte[24];
    SECURE_RANDOM.nextBytes(randomBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }

  @GetMapping(value = "/challenge/7/.git", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  @ResponseBody
  public ClassPathResource git() {
    return new ClassPathResource("lessons/challenges/challenge7/git.zip");
  }
}
