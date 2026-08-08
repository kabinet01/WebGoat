/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  private static final Map<String, String> COLORS = new HashMap<>();

  static {
    COLORS.put("admin", "green");
    COLORS.put("jerry", "orange");
    COLORS.put("tom", "purple");
    COLORS.put("larry", "yellow");
    COLORS.put("webgoat", "red");
  }

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(
      @RequestParam Map<String, Object> json, @CurrentUsername String currentUsername) {
    String securityQuestion = (String) json.getOrDefault("securityQuestion", "");
    String username = (String) json.getOrDefault("username", "");

    if ("webgoat".equalsIgnoreCase(username.toLowerCase())) {
      return failed(this).feedback("password-questions-wrong-user").build();
    }
    // A security question may only ever verify the identity of the account making the
    // request. The answers here have a tiny, guessable answer space (a handful of common
    // colors) with no rate limiting, so allowing the check to run against an arbitrary,
    // client-supplied username turns "forgot my own answer" into "brute-force anyone
    // else's account".
    if (!username.equalsIgnoreCase(currentUsername)) {
      return failed(this)
          .feedback("password-questions-unknown-user")
          .feedbackArgs(username)
          .build();
    }

    String validAnswer = COLORS.get(username.toLowerCase());
    if (validAnswer == null) {
      return failed(this)
          .feedback("password-questions-unknown-user")
          .feedbackArgs(username)
          .build();
    } else if (validAnswer.equals(securityQuestion)) {
      return success(this).build();
    }
    return failed(this).build();
  }
}
