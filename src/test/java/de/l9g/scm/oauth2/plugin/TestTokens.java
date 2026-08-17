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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Signs json web tokens for the tests, so the verification can be exercised against
 * real signatures instead of mocks. Deliberately independent of the production code:
 * it builds the tokens by hand, so a bug in {@link Jws} cannot hide itself by being
 * used on both sides.
 */
final class TestTokens {

  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

  private TestTokens() {
  }

  static KeyPair rsaKeyPair() {
    return keyPair("RSA", 2048);
  }

  static KeyPair ecKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      return generator.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not create an ec key pair", ex);
    }
  }

  private static KeyPair keyPair(String algorithm, int size) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
      generator.initialize(size);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not create a key pair", ex);
    }
  }

  /**
   * Signs a token with a private key.
   *
   * @param algorithm value of the {@code alg} header, e.g. {@code RS256}
   * @param jdkName   name of the jdk signature algorithm, e.g. {@code SHA256withRSA}
   * @param keyId     value of the {@code kid} header, may be {@code null}
   * @param claims    payload as json
   * @param key       private key of the issuer
   */
  static String signed(String algorithm, String jdkName, String keyId, String claims, PrivateKey key) {
    String signingInput = signingInput(algorithm, keyId, claims);
    try {
      Signature signature = Signature.getInstance(jdkName);
      signature.initSign(key);
      signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
      return signingInput + '.' + ENCODER.encodeToString(signature.sign());
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not sign the token", ex);
    }
  }

  /**
   * Signs a token with a shared secret (hmac).
   */
  static String signedWithSecret(String algorithm, String jdkName, String claims, String secret) {
    String signingInput = signingInput(algorithm, null, claims);
    try {
      Mac mac = Mac.getInstance(jdkName);
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), jdkName));
      byte[] signature = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
      return signingInput + '.' + ENCODER.encodeToString(signature);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not sign the token", ex);
    }
  }

  /**
   * Builds a token with a signature which does not belong to it.
   */
  static String withBrokenSignature(String algorithm, String keyId, String claims) {
    return signingInput(algorithm, keyId, claims) + '.' + ENCODER.encodeToString("not-a-signature".getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Builds an unsigned token, the {@code alg: none} case.
   */
  static String unsigned(String claims) {
    return signingInput("none", null, claims) + '.';
  }

  static String withHeader(String header, String claims) {
    return encode(header) + '.' + encode(claims) + '.' + ENCODER.encodeToString("signature".getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Builds the json web key set the identity provider would publish for a key pair.
   */
  static String jwks(String keyId, java.security.PublicKey publicKey) {
    if (publicKey instanceof RSAPublicKey) {
      RSAPublicKey rsa = (RSAPublicKey) publicKey;
      return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + keyId + "\""
        + ",\"n\":\"" + ENCODER.encodeToString(toUnsigned(rsa.getModulus().toByteArray())) + "\""
        + ",\"e\":\"" + ENCODER.encodeToString(toUnsigned(rsa.getPublicExponent().toByteArray())) + "\"}]}";
    }
    if (publicKey instanceof ECPublicKey) {
      ECPublicKey ec = (ECPublicKey) publicKey;
      return "{\"keys\":[{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"" + keyId + "\""
        + ",\"x\":\"" + ENCODER.encodeToString(toFixedLength(ec.getW().getAffineX().toByteArray(), 32)) + "\""
        + ",\"y\":\"" + ENCODER.encodeToString(toFixedLength(ec.getW().getAffineY().toByteArray(), 32)) + "\"}]}";
    }
    throw new IllegalArgumentException("unsupported key " + publicKey.getAlgorithm());
  }

  private static String signingInput(String algorithm, String keyId, String claims) {
    String header = keyId == null
      ? "{\"alg\":\"" + algorithm + "\",\"typ\":\"JWT\"}"
      : "{\"alg\":\"" + algorithm + "\",\"typ\":\"JWT\",\"kid\":\"" + keyId + "\"}";
    return encode(header) + '.' + encode(claims);
  }

  private static String encode(String value) {
    return ENCODER.encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * {@link java.math.BigInteger#toByteArray()} prepends a zero byte for positive
   * numbers whose highest bit is set; a json web key holds the value without it.
   */
  private static byte[] toUnsigned(byte[] value) {
    if (value.length > 1 && value[0] == 0) {
      byte[] stripped = new byte[value.length - 1];
      System.arraycopy(value, 1, stripped, 0, stripped.length);
      return stripped;
    }
    return value;
  }

  /**
   * Coordinates of an elliptic curve key are left padded to the length of the curve.
   */
  private static byte[] toFixedLength(byte[] value, int length) {
    byte[] unsigned = toUnsigned(value);
    if (unsigned.length == length) {
      return unsigned;
    }
    byte[] padded = new byte[length];
    System.arraycopy(unsigned, 0, padded, length - unsigned.length, unsigned.length);
    return padded;
  }
}
