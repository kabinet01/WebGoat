/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-feedback-hint1", "csrf-feedback-hint2", "csrf-feedback-hint3"})
public class CSRFFeedback implements AssignmentEndpoint {

  private static final String CSRF_TOKEN_SESSION_KEY = "csrf-feedback-token";

  private final LessonSession userSessionData;
  private final ObjectMapper objectMapper;

  public CSRFFeedback(LessonSession userSessionData, ObjectMapper objectMapper) {
    this.userSessionData = userSessionData;
    this.objectMapper = objectMapper;
  }

  /**
   * Issues a fresh, unpredictable, per-session anti-CSRF token that the feedback form must echo
   * back in its JSON body. Only a same-origin caller can retrieve this (a forged cross-site page
   * cannot read the response), so it cannot be reproduced by an attacker.
   */
  @GetMapping(path = "/csrf/feedback/token", produces = "application/json")
  @ResponseBody
  public Map<String, String> issueToken() {
    String token = UUID.randomUUID().toString();
    userSessionData.setValue(CSRF_TOKEN_SESSION_KEY, token);
    return Map.of("csrfToken", token);
  }

  @PostMapping(
      value = "/csrf/feedback/message",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(HttpServletRequest request, @RequestBody String feedback) {
    Map<?, ?> parsedFeedback;
    try {
      objectMapper.enable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS);
      objectMapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
      objectMapper.enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
      parsedFeedback = objectMapper.readValue(feedback.getBytes(), Map.class);
    } catch (IOException e) {
      return failed(this).feedback(ExceptionUtils.getStackTrace(e)).build();
    }

    // Primary defense: the submitted JSON must carry the per-session anti-CSRF token handed
    // out by /csrf/feedback/token. A cross-site forger cannot learn this value (same-origin
    // policy blocks it from reading that response), regardless of which Content-Type trick
    // (e.g. text/plain to dodge a JSON preflight) it uses to submit the forged request.
    Object submittedToken = parsedFeedback.get("csrfToken");
    boolean validToken =
        submittedToken != null
            && submittedToken.equals(userSessionData.getValue(CSRF_TOKEN_SESSION_KEY));

    // Secondary defense: reject requests whose Referer indicates a different host.
    boolean correctCSRF =
        requestContainsWebGoatCookie(request.getCookies())
            && validToken
            && sameOriginRequest(request);

    if (correctCSRF) {
      String flag = UUID.randomUUID().toString();
      userSessionData.setValue("csrf-feedback", flag);
      return success(this).feedback("csrf-feedback-success").feedbackArgs(flag).build();
    }
    return failed(this).build();
  }

  @PostMapping(path = "/csrf/feedback", produces = "application/json")
  @ResponseBody
  public AttackResult flag(@RequestParam("confirmFlagVal") String flag) {
    if (flag.equals(userSessionData.getValue("csrf-feedback"))) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  private boolean sameOriginRequest(HttpServletRequest request) {
    String referer = request.getHeader("Referer");
    String host = request.getHeader("Host");
    if (referer == null || host == null) {
      return true;
    }
    String[] refererArr = referer.split("/");
    return refererArr.length > 2 && refererArr[2].equals(host);
  }

  private boolean requestContainsWebGoatCookie(Cookie[] cookies) {
    if (cookies != null) {
      for (Cookie c : cookies) {
        if (c.getName().equals("JSESSIONID")) {
          return true;
        }
      }
    }
    return false;
  }
}
