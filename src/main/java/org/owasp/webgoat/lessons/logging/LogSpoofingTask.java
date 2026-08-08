/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output(username).build();
    }
    // Neutralise CR/LF and other control characters *before* the value is treated as something
    // that will be written to a log: once removed, user input can no longer be used to forge a
    // new, fake log line, regardless of how the remainder of the value is rendered.
    username = username.replaceAll("\\p{Cntrl}", "_");
    if (username.contains("<p>") || username.contains("<div>")) {
      return failed(this).output("Try to think of something simple ").build();
    }
    if (username.indexOf("<br/>") < username.indexOf("admin")) {
      return success(this).output(username).build();
    }
    return failed(this).output(username).build();
  }
}
