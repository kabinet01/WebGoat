/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import java.security.SecureRandom;
import java.util.Base64;

public interface SolutionConstants {

  // Only the 4-digit pincode (hidden in the challenge/logo image via steganography) is meant to
  // be discoverable. The rest of the password used to be a fixed literal, identical on every
  // install and published in this very source file, which handed an attacker the password
  // without ever having to find the hidden pincode. It is now generated fresh on every server
  // start instead.
  String PASSWORD = "!!webgoat_" + generateStartupSecret() + "_1234!!";

  static String generateStartupSecret() {
    byte[] randomBytes = new byte[9];
    new SecureRandom().nextBytes(randomBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }
}
