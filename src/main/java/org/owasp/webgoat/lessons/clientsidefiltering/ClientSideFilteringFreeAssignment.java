/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@AssignmentHints({
  "client.side.filtering.free.hint1",
  "client.side.filtering.free.hint2",
  "client.side.filtering.free.hint3"
})
public class ClientSideFilteringFreeAssignment implements AssignmentEndpoint {
  public static final String SUPER_COUPON_CODE = "get_it_for_free";

  @PostMapping("/clientSideFiltering/getItForFree")
  @ResponseBody
  public AttackResult completed(@RequestParam String checkoutCode) {
    // A client-visible coupon must never authorize a 100% discount. The original endpoint
    // accepted a static value that was shipped to every browser, so anyone could submit it
    // directly. There is no legitimate free checkout flow in this lesson; paid discount codes
    // are handled by the store endpoint instead.
    return failed(this).build();
  }
}
