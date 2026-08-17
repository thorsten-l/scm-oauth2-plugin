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
import org.apache.shiro.authc.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.SCMContextProvider;
import sonia.scm.Stage;
import sonia.scm.net.ahc.AdvancedHttpClient;
import sonia.scm.net.ahc.AdvancedHttpResponse;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Fetches the json web key set of the identity provider (rfc 7517) and turns it
 * into public keys.
 *
 * <p>Only asymmetric signature keys are of interest. Keys are skipped — not
 * rejected — when they are unusable for verification, because a key set regularly
 * contains additional keys, for example for encryption or with algorithms this
 * plugin does not support. A key set which yields no usable key at all is treated
 * as a failure by the caller.
 *
 * @see JwksProvider
 * @see TokenVerifier
 */
public class JwksClient {

  private static final Logger LOG = LoggerFactory.getLogger(JwksClient.class);

  /**
   * Curve names of the key set mapped to the names the jdk uses.
   */
  private static final Map<String, String> CURVES = Map.of(
    "P-256", "secp256r1",
    "P-384", "secp384r1",
    "P-521", "secp521r1"
  );

  private final SCMContextProvider contextProvider;
  private final AdvancedHttpClient httpClient;
  private final ObjectMapper objectMapper;

  @Inject
  public JwksClient(SCMContextProvider contextProvider, AdvancedHttpClient httpClient, ObjectMapper objectMapper) {
    this.contextProvider = contextProvider;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
  }

  /**
   * Fetches and parses the key set.
   *
   * @param jwksUrl url of the key set, taken from the discovery document or from
   *                the manual configuration
   * @return the usable keys of the set
   * @throws AuthenticationException if the set cannot be fetched or parsed
   */
  JsonWebKeys fetch(String jwksUrl) {
    return parse(fetchDocument(jwksUrl));
  }

  /**
   * Turns the document into keys. Separate from the request, so the parsing can be
   * tested without http.
   *
   * @param document the fetched key set
   * @return the usable keys of the set
   * @throws AuthenticationException if the document is not a key set
   */
  JsonWebKeys parse(JsonNode document) {
    JsonNode keys = document.get("keys");
    if (keys == null || !keys.isArray()) {
      throw new AuthenticationException("json web key set does not contain a keys array");
    }

    List<JsonWebKeys.Entry> entries = new ArrayList<>();
    for (JsonNode key : keys) {
      toEntry(key).ifPresent(entries::add);
    }

    LOG.debug("read {} usable keys of {} from the json web key set", entries.size(), keys.size());
    return JsonWebKeys.of(entries);
  }

  private Optional<JsonWebKeys.Entry> toEntry(JsonNode key) {
    String keyType = text(key, "kty");
    String use = text(key, "use");
    String keyId = text(key, "kid");

    // "use" is optional; if it is present it has to say signature
    if (!Strings.isNullOrEmpty(use) && !"sig".equals(use)) {
      return Optional.empty();
    }

    try {
      if ("RSA".equals(keyType)) {
        return Optional.of(new JsonWebKeys.Entry(keyId, keyType, toRsaKey(key)));
      }
      if ("EC".equals(keyType)) {
        return Optional.of(new JsonWebKeys.Entry(keyId, keyType, toEcKey(key)));
      }
      LOG.debug("skipping json web key of unsupported type '{}'", keyType);
    } catch (GeneralSecurityException | IllegalArgumentException | NullPointerException ex) {
      LOG.warn("skipping json web key '{}', because it could not be read", keyId, ex);
    }
    return Optional.empty();
  }

  private PublicKey toRsaKey(JsonNode key) throws GeneralSecurityException {
    BigInteger modulus = unsignedBigInteger(required(key, "n"));
    BigInteger exponent = unsignedBigInteger(required(key, "e"));
    return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
  }

  private PublicKey toEcKey(JsonNode key) throws GeneralSecurityException {
    String curve = required(key, "crv");
    String jdkCurve = CURVES.get(curve);
    if (jdkCurve == null) {
      throw new GeneralSecurityException("unsupported curve " + curve);
    }

    ECPoint point = new ECPoint(
      unsignedBigInteger(required(key, "x")),
      unsignedBigInteger(required(key, "y"))
    );

    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(jdkCurve));
    ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);

    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
  }

  /**
   * Key material is base64url encoded and always a positive number, the sign byte
   * of {@link BigInteger} must therefore be forced.
   */
  private BigInteger unsignedBigInteger(String base64Url) {
    return new BigInteger(1, Base64.getUrlDecoder().decode(base64Url));
  }

  private String required(JsonNode key, String field) throws GeneralSecurityException {
    String value = text(key, field);
    if (Strings.isNullOrEmpty(value)) {
      throw new GeneralSecurityException("json web key does not contain " + field);
    }
    return value;
  }

  private String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    return value.asText();
  }

  private JsonNode fetchDocument(String url) {
    AdvancedHttpResponse response;
    try {
      response = httpClient.get(url)
        .spanKind("OAuth2")
        .disableCertificateValidation(isDevelopmentStageActive())
        .request();
    } catch (IOException ex) {
      throw new AuthenticationException("failed to fetch json web key set", ex);
    }

    int statusCode = response.getStatus();
    if (statusCode != HttpServletResponse.SC_OK) {
      throw new AuthenticationException("failed to fetch json web key set, server returned status " + statusCode);
    }

    try {
      return objectMapper.readTree(response.contentAsString());
    } catch (IOException ex) {
      throw new AuthenticationException("failed to parse json web key set", ex);
    }
  }

  private boolean isDevelopmentStageActive() {
    return contextProvider.getStage() == Stage.DEVELOPMENT;
  }
}
