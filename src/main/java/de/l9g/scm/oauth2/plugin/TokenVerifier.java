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

import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Clock;
import java.util.Optional;

/**
 * Verifies the tokens of the identity provider: signature first, then the claims.
 *
 * <h2>Two levels of strictness</h2>
 *
 * The id token is an authentication statement and is therefore validated strictly
 * according to OIDC Core 3.1.3.7 — a token which is present but invalid aborts the
 * login. The access token is only read to import roles; an anomaly there costs the
 * roles, but does not fail the login, since the token was received over an
 * authenticated tls connection and the identity itself comes from the userinfo
 * endpoint.
 *
 * <h2>What happens without key material</h2>
 *
 * Verification needs either a key set url (from the discovery document or from the
 * configuration) or, for the {@code HS} family, the client secret. If neither is
 * available, no token is verified and none is used: the id token is discarded and no
 * roles are imported, each with a warning naming the missing configuration. Data
 * which cannot be verified is never trusted.
 *
 * @see Jws
 * @see JwsAlgorithm
 * @see JwksProvider
 */
public class TokenVerifier {

  private static final Logger LOG = LoggerFactory.getLogger(TokenVerifier.class);

  /**
   * Tolerance for clock differences between this instance and the identity provider.
   */
  private static final long CLOCK_SKEW_IN_SECONDS = 60L;

  private final OAuth2Context context;
  private final EndpointResolver endpointResolver;
  private final JwksProvider jwksProvider;
  private final ObjectMapper objectMapper;
  private final Clock clock;

  @Inject
  public TokenVerifier(OAuth2Context context, EndpointResolver endpointResolver, JwksProvider jwksProvider, ObjectMapper objectMapper) {
    this(context, endpointResolver, jwksProvider, objectMapper, Clock.systemUTC());
  }

  TokenVerifier(OAuth2Context context, EndpointResolver endpointResolver, JwksProvider jwksProvider, ObjectMapper objectMapper, Clock clock) {
    this.context = context;
    this.endpointResolver = endpointResolver;
    this.jwksProvider = jwksProvider;
    this.objectMapper = objectMapper;
    this.clock = clock;
  }

  /**
   * Verifies an id token.
   *
   * @param idToken      id token of the token response, may be {@code null} if the
   *                     provider does not issue one
   * @param expectedNonce nonce of the authorization request; if it is set, the token
   *                     has to carry the same value
   * @return the verified claims, empty if there is no token or if it cannot be
   *         verified for lack of key material
   * @throws AuthenticationException if a token is present but invalid
   */
  public Optional<JsonNode> verifyIdToken(String idToken, String expectedNonce) {
    if (Strings.isNullOrEmpty(idToken)) {
      LOG.debug("token response does not contain an id token");
      return Optional.empty();
    }

    Jws jws = Jws.parse(idToken, objectMapper)
      .orElseThrow(() -> new AuthenticationException("id token is not a json web signature"));

    JwsAlgorithm algorithm = JwsAlgorithm.of(jws.getAlgorithm())
      .orElseThrow(() -> new AuthenticationException("id token is signed with the unsupported algorithm " + jws.getAlgorithm()));

    if (jws.hasUnsupportedCriticalHeader()) {
      throw new AuthenticationException("id token requires an unsupported critical header extension");
    }

    if (!canVerify(algorithm)) {
      LOG.warn(
        "cannot verify the id token, because no json web key set is available; "
          + "configure a discovery url or the key set url, otherwise the sso logout works without an id token hint"
      );
      return Optional.empty();
    }

    if (!isSignatureValid(jws, algorithm)) {
      throw new AuthenticationException("signature of the id token is invalid");
    }

    JsonNode claims = jws.getPayload();
    validateIssuer(claims, "id token");
    validateAudience(claims);
    validateLifetime(claims, "id token", true);
    validateNonce(claims, expectedNonce);

    LOG.debug("id token verified, signed with {}", algorithm.name());
    return Optional.of(claims);
  }

  /**
   * Verifies an access token, as far as that is possible: an access token is
   * addressed to the resource server, not to this client, therefore the audience is
   * not required to contain the client id.
   *
   * @param accessToken access token of the token response
   * @return the verified claims, empty if the token is opaque, cannot be verified or
   *         does not stand up to verification
   */
  public Optional<JsonNode> verifyAccessToken(String accessToken) {
    if (Strings.isNullOrEmpty(accessToken)) {
      return Optional.empty();
    }

    Optional<Jws> parsed = Jws.parse(accessToken, objectMapper);
    if (!parsed.isPresent()) {
      LOG.debug("access token is not a json web signature, it is probably opaque");
      return Optional.empty();
    }
    Jws jws = parsed.get();

    Optional<JwsAlgorithm> algorithm = JwsAlgorithm.of(jws.getAlgorithm());
    if (!algorithm.isPresent()) {
      LOG.warn("access token is signed with the unsupported algorithm {}", jws.getAlgorithm());
      return Optional.empty();
    }

    if (jws.hasUnsupportedCriticalHeader()) {
      LOG.warn("access token requires an unsupported critical header extension");
      return Optional.empty();
    }

    if (!canVerify(algorithm.get())) {
      LOG.warn(
        "cannot verify the access token, because no json web key set is available; "
          + "configure a discovery url or the key set url to import roles from the access token"
      );
      return Optional.empty();
    }

    if (!isSignatureValid(jws, algorithm.get())) {
      LOG.warn("signature of the access token is invalid, no roles are imported from it");
      return Optional.empty();
    }

    try {
      validateIssuer(jws.getPayload(), "access token");
      validateLifetime(jws.getPayload(), "access token", false);
    } catch (AuthenticationException ex) {
      LOG.warn("access token did not stand up to verification, no roles are imported from it", ex);
      return Optional.empty();
    }

    LOG.debug("access token verified, signed with {}", algorithm.get().name());
    return Optional.of(jws.getPayload());
  }

  /**
   * @return {@code true} if the material needed for this algorithm is configured
   */
  private boolean canVerify(JwsAlgorithm algorithm) {
    if (algorithm.isSymmetric()) {
      return !Strings.isNullOrEmpty(context.get().getClientSecret());
    }
    return !Strings.isNullOrEmpty(jwksUrl());
  }

  private boolean isSignatureValid(Jws jws, JwsAlgorithm algorithm) {
    if (algorithm.isSymmetric()) {
      // the hs family signs with the client secret, a key of the provider is never
      // used for it — this is what stops an algorithm confusion attack
      return jws.verify(algorithm, context.get().getClientSecret());
    }

    Optional<PublicKey> key = jwksProvider.resolve(jwksUrl(), jws.getKeyId(), algorithm.getKeyType().name());
    if (!key.isPresent()) {
      LOG.warn("the json web key set does not contain a {} key with the id '{}'", algorithm.getKeyType(), jws.getKeyId());
      return false;
    }
    return jws.verify(algorithm, key.get());
  }

  /**
   * The key set url comes from the discovery document; if the endpoints are
   * configured manually, it has to be configured as well.
   */
  private String jwksUrl() {
    return endpointResolver.resolve().getJwksUrl();
  }

  /**
   * The issuer is only known when a discovery document is used; with a manual
   * configuration there is nothing to compare against.
   */
  private void validateIssuer(JsonNode claims, String tokenName) {
    String expected = endpointResolver.resolve().getIssuer();
    if (Strings.isNullOrEmpty(expected)) {
      return;
    }
    String issuer = text(claims, "iss");
    if (!expected.equals(issuer)) {
      throw new AuthenticationException("the " + tokenName + " was issued by '" + issuer + "' instead of '" + expected + "'");
    }
  }

  /**
   * The id token has to be addressed to this client (OIDC Core 3.1.3.7 (3)); if the
   * issuer names an authorized party, it has to be this client as well (5).
   */
  private void validateAudience(JsonNode claims) {
    String clientId = context.get().getClientId();
    if (!contains(claims.get("aud"), clientId)) {
      throw new AuthenticationException("the id token is not addressed to this client");
    }

    String authorizedParty = text(claims, "azp");
    if (!Strings.isNullOrEmpty(authorizedParty) && !authorizedParty.equals(clientId)) {
      throw new AuthenticationException("the id token was issued for the client '" + authorizedParty + "'");
    }
  }

  /**
   * @param expirationRequired the id token must carry an expiry, for an access token
   *                           it is checked only if present
   */
  private void validateLifetime(JsonNode claims, String tokenName, boolean expirationRequired) {
    long now = clock.millis() / 1000L;

    JsonNode expiration = claims.get("exp");
    if (expiration == null || !expiration.canConvertToLong()) {
      if (expirationRequired) {
        throw new AuthenticationException("the " + tokenName + " does not contain an expiry");
      }
    } else if (expiration.asLong() + CLOCK_SKEW_IN_SECONDS < now) {
      throw new AuthenticationException("the " + tokenName + " has expired");
    }

    JsonNode notBefore = claims.get("nbf");
    if (notBefore != null && notBefore.canConvertToLong() && notBefore.asLong() - CLOCK_SKEW_IN_SECONDS > now) {
      throw new AuthenticationException("the " + tokenName + " is not valid yet");
    }

    JsonNode issuedAt = claims.get("iat");
    if (issuedAt != null && issuedAt.canConvertToLong() && issuedAt.asLong() - CLOCK_SKEW_IN_SECONDS > now) {
      throw new AuthenticationException("the " + tokenName + " was issued in the future");
    }
  }

  /**
   * If a nonce was sent with the authorization request, the id token has to carry it
   * (OIDC Core 3.1.3.7 (11)). This binds the token to this very login and makes a
   * replay of an id token of another session useless.
   */
  private void validateNonce(JsonNode claims, String expectedNonce) {
    if (Strings.isNullOrEmpty(expectedNonce)) {
      return;
    }

    String nonce = text(claims, "nonce");
    if (Strings.isNullOrEmpty(nonce)) {
      throw new AuthenticationException("the id token does not contain the nonce of the authorization request");
    }
    if (!MessageDigest.isEqual(nonce.getBytes(StandardCharsets.UTF_8), expectedNonce.getBytes(StandardCharsets.UTF_8))) {
      throw new AuthenticationException("the nonce of the id token does not match the authorization request");
    }
  }

  /**
   * The audience is a single value or an array of values.
   */
  private boolean contains(JsonNode audience, String value) {
    if (audience == null || audience.isNull() || Strings.isNullOrEmpty(value)) {
      return false;
    }
    if (audience.isArray()) {
      for (JsonNode entry : audience) {
        if (value.equals(entry.asText())) {
          return true;
        }
      }
      return false;
    }
    return value.equals(audience.asText());
  }

  private String text(JsonNode claims, String name) {
    JsonNode value = claims.get(name);
    if (value == null || value.isNull()) {
      return null;
    }
    return value.asText();
  }
}
