/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  // The cookie value must not be a reversible encoding of the username: anyone who can see one
  // valid cookie (e.g. by logging in themselves) could otherwise recompute the encoding for any
  // other username and forge a cookie for them. Instead, the username is bound to a server-side
  // secret with an HMAC, so only the server can mint a value that will pass verification.

  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final int SIGNATURE_HEX_LENGTH = 64; // SHA-256 -> 32 bytes -> 64 hex chars
  private static final SecretKeySpec SECRET_KEY = generateSecretKey();

  private EncDec() {}

  private static SecretKeySpec generateSecretKey() {
    byte[] keyBytes = new byte[32];
    new SecureRandom().nextBytes(keyBytes);
    return new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
  }

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String username = value.toLowerCase();
    String payload = username + sign(username);
    return base64Encode(payload);
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String payload = base64Decode(encodedValue);
    if (payload.length() <= SIGNATURE_HEX_LENGTH) {
      throw new IllegalArgumentException("Invalid cookie value");
    }

    String username = payload.substring(0, payload.length() - SIGNATURE_HEX_LENGTH);
    String signature = payload.substring(payload.length() - SIGNATURE_HEX_LENGTH);

    if (!MessageDigest.isEqual(
        signature.getBytes(StandardCharsets.UTF_8),
        sign(username).getBytes(StandardCharsets.UTF_8))) {
      throw new IllegalArgumentException("Invalid cookie signature");
    }

    return username;
  }

  private static String sign(final String username) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(SECRET_KEY);
      byte[] rawHmac = mac.doFinal(username.getBytes(StandardCharsets.UTF_8));
      return toHex(rawHmac);
    } catch (Exception e) {
      throw new IllegalStateException("Unable to sign cookie value", e);
    }
  }

  private static String toHex(final byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  private static String base64Encode(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String base64Decode(final String value) {
    byte[] decoded = Base64.getDecoder().decode(value.getBytes(StandardCharsets.UTF_8));
    return new String(decoded, StandardCharsets.UTF_8);
  }
}
