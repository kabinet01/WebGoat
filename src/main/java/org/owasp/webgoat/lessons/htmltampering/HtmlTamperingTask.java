/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  // Authoritative, server-side price for the item. The client is never trusted to supply it.
  private static final float PRICE = 2999.99f;

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    float qty = Float.parseFloat(QTY);
    float submittedTotal = Float.parseFloat(Total);
    float expectedTotal = qty * PRICE;
    // Re-derive the total server-side from the known price instead of trusting the total
    // the client submitted; reject anything that does not match (e.g. a tampered/lowered
    // total).
    if (Math.abs(expectedTotal - submittedTotal) > 0.01f) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    return success(this).feedback("html-tampering.tamper.success").build();
  }
}
