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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;

/**
 * A token in the compact serialization of a json web signature (rfc 7515),
 * split into its three parts and with its signature verifiable.
 *
 * <p>The class only parses and verifies; which claims a valid token has to contain
 * is decided by {@link TokenVerifier}. Parsing never fails with an exception, a
 * value which is not a json web signature simply yields an empty optional — an
 * access token may legitimately be opaque.
 *
 * <p>Security relevant properties of the implementation:
 *
 * <ul>
 *   <li>the algorithm is taken from an allow list, {@code none} and unknown values
 *       are rejected</li>
 *   <li>the algorithm determines which kind of key is accepted, so a token cannot
 *       force the verification of an rsa signature with a symmetric key or the other
 *       way round (algorithm confusion)</li>
 *   <li>a {@code crit} header is rejected, because this plugin does not implement any
 *       extension the issuer could declare as mandatory</li>
 *   <li>signature bytes are compared through the jdk primitives; the hmac comparison
 *       runs in constant time</li>
 * </ul>
 */
final class Jws {

  private final JsonNode header;
  private final JsonNode payload;
  private final byte[] signingInput;
  private final byte[] signature;

  private Jws(JsonNode header, JsonNode payload, byte[] signingInput, byte[] signature) {
    this.header = header;
    this.payload = payload;
    this.signingInput = signingInput;
    this.signature = signature;
  }

  /**
   * Splits a token into its parts.
   *
   * @param token        the token, may be {@code null}
   * @param objectMapper mapper for header and payload
   * @return the parsed token, empty if the value is not a json web signature
   */
  static Optional<Jws> parse(String token, ObjectMapper objectMapper) {
    if (Strings.isNullOrEmpty(token)) {
      return Optional.empty();
    }

    // header.payload.signature — an opaque token has no dots and ends up here
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3) {
      return Optional.empty();
    }

    try {
      Base64.Decoder decoder = Base64.getUrlDecoder();
      JsonNode header = objectMapper.readTree(new String(decoder.decode(parts[0]), StandardCharsets.UTF_8));
      JsonNode payload = objectMapper.readTree(new String(decoder.decode(parts[1]), StandardCharsets.UTF_8));
      byte[] signature = decoder.decode(parts[2]);
      byte[] signingInput = (parts[0] + '.' + parts[1]).getBytes(StandardCharsets.US_ASCII);

      if (header == null || payload == null || !payload.isObject()) {
        return Optional.empty();
      }
      return Optional.of(new Jws(header, payload, signingInput, signature));
    } catch (IOException | IllegalArgumentException ex) {
      return Optional.empty();
    }
  }

  JsonNode getPayload() {
    return payload;
  }

  /**
   * @return value of the {@code alg} header, or {@code null} if it is missing
   */
  String getAlgorithm() {
    return text("alg");
  }

  /**
   * @return value of the {@code kid} header, or {@code null} if the issuer did not
   *         name a key
   */
  String getKeyId() {
    return text("kid");
  }

  /**
   * @return {@code true} if the header declares an extension as mandatory which
   *         this implementation does not know
   */
  boolean hasUnsupportedCriticalHeader() {
    JsonNode critical = header.get("crit");
    return critical != null && !critical.isNull();
  }

  /**
   * Verifies the signature with a public key.
   *
   * @param algorithm the already validated algorithm
   * @param key       key of the identity provider
   * @return {@code true} if the signature belongs to this token
   */
  boolean verify(JwsAlgorithm algorithm, PublicKey key) {
    return algorithm.verify(signingInput, signature, key);
  }

  /**
   * Verifies the signature with the shared client secret (hmac).
   *
   * @param algorithm the already validated algorithm
   * @param secret    client secret of the configuration
   * @return {@code true} if the signature belongs to this token
   */
  boolean verify(JwsAlgorithm algorithm, String secret) {
    byte[] expected = algorithm.mac(signingInput, secret);
    return expected != null && MessageDigest.isEqual(expected, signature);
  }

  private String text(String field) {
    JsonNode value = header.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    return value.asText();
  }
}
