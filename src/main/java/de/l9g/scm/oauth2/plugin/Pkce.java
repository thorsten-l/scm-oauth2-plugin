/*
 * Copyright (c) 2026 - present Thorsten Ludewig (t.ludewig@gmail.com)
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/.
 */

package de.l9g.scm.oauth2.plugin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Proof key for code exchange (rfc 7636). Protects the authorization code
 * against interception and injection, because the code can only be redeemed
 * together with the verifier of the request which started the flow.
 */
final class Pkce {

  static final String METHOD = "S256";

  private static final int VERIFIER_LENGTH_IN_BYTES = 32;

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

  private Pkce() {
  }

  static String createVerifier() {
    byte[] bytes = new byte[VERIFIER_LENGTH_IN_BYTES];
    RANDOM.nextBytes(bytes);
    return ENCODER.encodeToString(bytes);
  }

  static String createChallenge(String verifier) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
      return ENCODER.encodeToString(digest);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("sha-256 is not available", ex);
    }
  }
}
