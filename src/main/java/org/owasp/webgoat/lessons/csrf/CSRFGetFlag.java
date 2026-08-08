/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  private static final String CSRF_TOKEN_SESSION_KEY = "csrf-get-flag-token";

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  /**
   * Issues a fresh, unpredictable, per-session anti-CSRF token that must be echoed back on
   * /csrf/basic-get-flag. A forged request (blind, cross-site, or launched from a local file://
   * page with no Referer at all) has no way to read this response and therefore cannot learn the
   * value it needs to supply.
   */
  @GetMapping(path = "/csrf/basic-get-flag/token", produces = {"application/json"})
  @ResponseBody
  public Map<String, String> issueToken() {
    String token = UUID.randomUUID().toString();
    userSessionData.setValue(CSRF_TOKEN_SESSION_KEY, token);
    return Map.of("token", token);
  }

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    String host = (req.getHeader("host") == null) ? "NULL" : req.getHeader("host");
    String referer = (req.getHeader("referer") == null) ? "NULL" : req.getHeader("referer");

    // Primary defense: the request must carry the per-session anti-CSRF token.
    Object expectedToken = userSessionData.getValue(CSRF_TOKEN_SESSION_KEY);
    String submittedToken = req.getParameter("token");
    boolean validToken =
        expectedToken != null && submittedToken != null && submittedToken.equals(expectedToken);

    // Secondary defense: if a Referer is present, it must point back at this host.
    boolean sameOrigin = true;
    if (!referer.equals("NULL")) {
      String[] refererArr = referer.split("/");
      sameOrigin = refererArr.length > 2 && refererArr[2].equals(host);
    }

    if (validToken && sameOrigin) {
      Random random = new Random();
      userSessionData.setValue("csrf-get-success", random.nextInt(65536));
      response.put("success", true);
      if ("true".equals(req.getParameter("csrf"))) {
        response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
      } else {
        response.put("message", pluginMessages.getMessage("csrf-get-other-referer.success"));
      }
      response.put("flag", userSessionData.getValue("csrf-get-success"));
    } else {
      response.put("success", false);
      response.put("message", "Appears the request came from the original host");
      response.put("flag", null);
    }

    return response;
  }
}
