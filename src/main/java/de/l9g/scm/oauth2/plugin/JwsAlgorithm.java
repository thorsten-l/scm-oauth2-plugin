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

import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Optional;

/**
 * The signature algorithms this plugin accepts, with the mapping to the jdk
 * primitives. Everything which is not listed here is rejected — in particular
 * {@code none}.
 *
 * <p>{@link #getKeyType()} is what prevents algorithm confusion: an {@code RS256}
 * token is only ever verified with an rsa key from the key set, an {@code ES256}
 * token only with an elliptic curve key, and the {@code HS} family only with the
 * client secret, never with a key of the identity provider.
 *
 * <p>Note on elliptic curves: a json web signature carries {@code r} and {@code s}
 * concatenated, while the jdk signature classes expect them der encoded. The jdk
 * offers the concatenated form as its own algorithm name ({@code inP1363Format},
 * available since java 11), which is used here instead of converting by hand.
 */
enum JwsAlgorithm {

  RS256("SHA256withRSA", KeyType.RSA),
  RS384("SHA384withRSA", KeyType.RSA),
  RS512("SHA512withRSA", KeyType.RSA),

  PS256("RSASSA-PSS", KeyType.RSA, new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
  PS384("RSASSA-PSS", KeyType.RSA, new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)),
  PS512("RSASSA-PSS", KeyType.RSA, new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)),

  ES256("SHA256withECDSAinP1363Format", KeyType.EC),
  ES384("SHA384withECDSAinP1363Format", KeyType.EC),
  ES512("SHA512withECDSAinP1363Format", KeyType.EC),

  HS256("HmacSHA256", KeyType.SECRET),
  HS384("HmacSHA384", KeyType.SECRET),
  HS512("HmacSHA512", KeyType.SECRET);

  private static final Logger LOG = LoggerFactory.getLogger(JwsAlgorithm.class);

  private final String jdkName;
  private final KeyType keyType;
  private final PSSParameterSpec parameterSpec;

  JwsAlgorithm(String jdkName, KeyType keyType) {
    this(jdkName, keyType, null);
  }

  JwsAlgorithm(String jdkName, KeyType keyType, PSSParameterSpec parameterSpec) {
    this.jdkName = jdkName;
    this.keyType = keyType;
    this.parameterSpec = parameterSpec;
  }

  /**
   * Resolves the value of the {@code alg} header.
   *
   * @param algorithm value of the header, may be {@code null}
   * @return the algorithm, empty if it is missing, unknown or {@code none}
   */
  static Optional<JwsAlgorithm> of(String algorithm) {
    if (Strings.isNullOrEmpty(algorithm)) {
      return Optional.empty();
    }
    for (JwsAlgorithm candidate : values()) {
      if (candidate.name().equals(algorithm)) {
        return Optional.of(candidate);
      }
    }
    return Optional.empty();
  }

  /**
   * @return the key type this algorithm requires
   */
  KeyType getKeyType() {
    return keyType;
  }

  /**
   * @return {@code true} if the signature is created with the client secret instead
   *         of a published key
   */
  boolean isSymmetric() {
    return keyType == KeyType.SECRET;
  }

  /**
   * Verifies an asymmetric signature.
   *
   * @param signingInput the signed bytes, header and payload separated by a dot
   * @param signature    signature bytes of the token
   * @param key          key of the identity provider
   * @return {@code true} if the signature is valid
   */
  boolean verify(byte[] signingInput, byte[] signature, PublicKey key) {
    if (!matches(key)) {
      // must not happen, the caller resolves the key by key type
      LOG.warn("key of type {} does not fit algorithm {}", key.getAlgorithm(), name());
      return false;
    }

    try {
      Signature verifier = Signature.getInstance(jdkName);
      if (parameterSpec != null) {
        verifier.setParameter(parameterSpec);
      }
      verifier.initVerify(key);
      verifier.update(signingInput);
      return verifier.verify(signature);
    } catch (GeneralSecurityException ex) {
      LOG.debug("signature of algorithm {} could not be verified", name(), ex);
      return false;
    }
  }

  /**
   * Calculates the expected hmac of a symmetric signature.
   *
   * @param signingInput the signed bytes
   * @param secret       client secret
   * @return the expected signature, or {@code null} if it cannot be calculated
   */
  byte[] mac(byte[] signingInput, String secret) {
    if (keyType != KeyType.SECRET || Strings.isNullOrEmpty(secret)) {
      return null;
    }
    try {
      Mac mac = Mac.getInstance(jdkName);
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), jdkName));
      return mac.doFinal(signingInput);
    } catch (GeneralSecurityException ex) {
      LOG.debug("hmac of algorithm {} could not be calculated", name(), ex);
      return null;
    }
  }

  private boolean matches(PublicKey key) {
    switch (keyType) {
      case RSA:
        return key instanceof RSAPublicKey;
      case EC:
        return key instanceof ECPublicKey;
      default:
        return false;
    }
  }

  /**
   * Kind of key an algorithm family requires. The names {@code RSA} and {@code EC}
   * are the {@code kty} values of a json web key set.
   */
  enum KeyType {
    RSA, EC, SECRET
  }
}
