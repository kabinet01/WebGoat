/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import jakarta.servlet.http.HttpSession;
import java.security.SecureRandom;

/**
 * Generates and stores the "unique code" that proves a user genuinely retrieved something
 * WebGoat sent to WebWolf (a landing-page hit or a mailbox message).
 *
 * <p>The code used to be {@code StringUtils.reverse(username)}: a value derivable from public
 * information alone, so it could be satisfied without ever visiting WebWolf. Generating it with
 * a secure random source and only handing it out through the session that owns it restores the
 * intended proof of retrieval, tying success to a real, unpredictable server-side secret instead
 * of a formula anyone can compute for themselves.
 */
final class WebWolfCode {

  static final String SESSION_KEY = "webwolf-unique-code";

  private static final String ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  private static final SecureRandom RANDOM = new SecureRandom();

  private WebWolfCode() {}

  static synchronized String getOrCreate(HttpSession session, String username) {
    String code = (String) session.getAttribute(SESSION_KEY);
    if (code == null) {
      code = generate(Math.max(username.length(), 6));
      session.setAttribute(SESSION_KEY, code);
    }
    return code;
  }

  private static String generate(int length) {
    StringBuilder code = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
      code.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
    }
    return code.toString();
  }
}
