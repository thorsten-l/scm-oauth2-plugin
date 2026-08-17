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
import org.apache.shiro.authc.AuthenticationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Tests the token verification against real signatures: an rsa, an elliptic curve
 * and an hmac signed token are accepted, while every manipulation is rejected —
 * broken signature, {@code alg: none}, an algorithm which is not supported, a
 * critical header, the wrong key, a foreign issuer, a foreign audience, an expired
 * token and a wrong or missing nonce.
 *
 * <p>The two levels of strictness are covered as well: an invalid id token aborts the
 * login with an exception, while an invalid access token only yields no claims, and
 * without key material nothing is verified and nothing is used.
 */
@ExtendWith(MockitoExtension.class)
class TokenVerifierTest {

  private static final String CLIENT_ID = "scm-client";
  private static final String CLIENT_SECRET = "the-client-secret-which-is-long-enough";
  private static final String ISSUER = "https://idp.hitchhiker.com/realms/main";
  private static final String JWKS_URL = "https://idp.hitchhiker.com/realms/main/protocol/openid-connect/certs";
  private static final String KEY_ID = "the-key";
  private static final String NONCE = "the-nonce";

  private static final Instant NOW = Instant.parse("2026-08-17T12:00:00Z");

  @Mock
  private OAuth2Context context;

  @Mock
  private EndpointResolver endpointResolver;

  @Mock
  private JwksProvider jwksProvider;

  private final OAuth2Configuration configuration = new OAuth2Configuration();
  private final ObjectMapper objectMapper = new ObjectMapper();

  private KeyPair rsaKeyPair;
  private TokenVerifier verifier;

  @BeforeEach
  void setUpVerifier() {
    rsaKeyPair = TestTokens.rsaKeyPair();

    configuration.setClientId(CLIENT_ID);
    configuration.setClientSecret(CLIENT_SECRET);
    lenient().when(context.get()).thenReturn(configuration);
    lenient().when(endpointResolver.resolve()).thenReturn(
      new Endpoints("a", "t", "u", null, JWKS_URL, ISSUER, java.util.Set.of())
    );
    lenient().when(jwksProvider.resolve(JWKS_URL, KEY_ID, "RSA")).thenReturn(Optional.of(rsaKeyPair.getPublic()));

    verifier = new TokenVerifier(
      context, endpointResolver, jwksProvider, objectMapper, Clock.fixed(NOW, ZoneOffset.UTC)
    );
  }

  @Test
  void shouldVerifyRsaSignedIdToken() {
    String idToken = rsaSigned(claims(NONCE));

    Optional<JsonNode> claims = verifier.verifyIdToken(idToken, NONCE);

    assertThat(claims).isPresent();
    assertThat(claims.get().get("sub").asText()).isEqualTo("trillian");
  }

  @Test
  void shouldVerifyEcSignedIdToken() {
    KeyPair ecKeyPair = TestTokens.ecKeyPair();
    when(jwksProvider.resolve(JWKS_URL, KEY_ID, "EC")).thenReturn(Optional.of(ecKeyPair.getPublic()));
    String idToken = TestTokens.signed("ES256", "SHA256withECDSAinP1363Format", KEY_ID, claims(NONCE), ecKeyPair.getPrivate());

    assertThat(verifier.verifyIdToken(idToken, NONCE)).isPresent();
  }

  @Test
  void shouldVerifyIdTokenSignedWithTheClientSecret() {
    // the hs family signs symmetrically, no key of the provider is involved
    String idToken = TestTokens.signedWithSecret("HS256", "HmacSHA256", claims(NONCE), CLIENT_SECRET);

    assertThat(verifier.verifyIdToken(idToken, NONCE)).isPresent();
  }

  @Test
  void shouldRejectIdTokenSignedWithAnotherSecret() {
    String idToken = TestTokens.signedWithSecret("HS256", "HmacSHA256", claims(NONCE), "the-secret-of-someone-else");

    assertInvalid(idToken, "signature");
  }

  @Test
  void shouldRejectBrokenSignature() {
    assertInvalid(TestTokens.withBrokenSignature("RS256", KEY_ID, claims(NONCE)), "signature");
  }

  @Test
  void shouldRejectUnsignedIdToken() {
    // alg: none must never be accepted
    assertInvalid(TestTokens.unsigned(claims(NONCE)), "unsupported algorithm");
  }

  @Test
  void shouldRejectUnsupportedAlgorithm() {
    String idToken = TestTokens.withHeader("{\"alg\":\"RSA1_5\"}", claims(NONCE));

    assertInvalid(idToken, "unsupported algorithm");
  }

  @Test
  void shouldRejectCriticalHeader() {
    String idToken = TestTokens.withHeader("{\"alg\":\"RS256\",\"crit\":[\"exp\"]}", claims(NONCE));

    assertInvalid(idToken, "critical header");
  }

  @Test
  void shouldRejectIdTokenSignedWithAnotherKey() {
    KeyPair otherKeyPair = TestTokens.rsaKeyPair();
    String idToken = TestTokens.signed("RS256", "SHA256withRSA", KEY_ID, claims(NONCE), otherKeyPair.getPrivate());

    assertInvalid(idToken, "signature");
  }

  @Test
  void shouldRejectIdTokenWithUnknownKeyId() {
    when(jwksProvider.resolve(JWKS_URL, "another-key", "RSA")).thenReturn(Optional.empty());
    String idToken = TestTokens.signed("RS256", "SHA256withRSA", "another-key", claims(NONCE), rsaKeyPair.getPrivate());

    assertInvalid(idToken, "signature");
  }

  @Test
  void shouldRejectForeignIssuer() {
    String idToken = rsaSigned(claims(NONCE).replace(ISSUER, "https://evil.hitchhiker.com"));

    assertInvalid(idToken, "issued by");
  }

  @Test
  void shouldRejectForeignAudience() {
    String idToken = rsaSigned(claims(NONCE).replace("\"" + CLIENT_ID + "\"", "\"another-client\""));

    assertInvalid(idToken, "not addressed to this client");
  }

  @Test
  void shouldRejectForeignAuthorizedParty() {
    String idToken = rsaSigned("{"
      + "\"iss\":\"" + ISSUER + "\",\"aud\":[\"" + CLIENT_ID + "\",\"account\"],"
      + "\"azp\":\"another-client\",\"sub\":\"trillian\",\"exp\":" + expiry() + ",\"nonce\":\"" + NONCE + "\"}");

    assertInvalid(idToken, "another-client");
  }

  @Test
  void shouldAcceptAudienceArrayContainingTheClient() {
    String idToken = rsaSigned("{"
      + "\"iss\":\"" + ISSUER + "\",\"aud\":[\"account\",\"" + CLIENT_ID + "\"],"
      + "\"azp\":\"" + CLIENT_ID + "\",\"sub\":\"trillian\",\"exp\":" + expiry() + ",\"nonce\":\"" + NONCE + "\"}");

    assertThat(verifier.verifyIdToken(idToken, NONCE)).isPresent();
  }

  @Test
  void shouldRejectExpiredIdToken() {
    String idToken = rsaSigned("{"
      + "\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\",\"sub\":\"trillian\","
      + "\"exp\":" + (NOW.getEpochSecond() - 3600) + ",\"nonce\":\"" + NONCE + "\"}");

    assertInvalid(idToken, "expired");
  }

  @Test
  void shouldRejectIdTokenWithoutExpiry() {
    String idToken = rsaSigned("{"
      + "\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\",\"sub\":\"trillian\","
      + "\"nonce\":\"" + NONCE + "\"}");

    assertInvalid(idToken, "expiry");
  }

  @Test
  void shouldAcceptTokenWhichExpiredWithinTheClockSkew() {
    String idToken = rsaSigned("{"
      + "\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\",\"sub\":\"trillian\","
      + "\"exp\":" + (NOW.getEpochSecond() - 30) + ",\"nonce\":\"" + NONCE + "\"}");

    assertThat(verifier.verifyIdToken(idToken, NONCE)).isPresent();
  }

  @Test
  void shouldRejectTokenIssuedInTheFuture() {
    String idToken = rsaSigned("{"
      + "\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\",\"sub\":\"trillian\","
      + "\"exp\":" + expiry() + ",\"iat\":" + (NOW.getEpochSecond() + 3600) + ",\"nonce\":\"" + NONCE + "\"}");

    assertInvalid(idToken, "future");
  }

  @Test
  void shouldRejectWrongNonce() {
    String idToken = rsaSigned(claims("the-nonce-of-another-login"));

    assertInvalid(idToken, "nonce");
  }

  @Test
  void shouldRejectMissingNonce() {
    String idToken = rsaSigned("{"
      + "\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\",\"sub\":\"trillian\","
      + "\"exp\":" + expiry() + "}");

    assertInvalid(idToken, "nonce");
  }

  @Test
  void shouldRejectSomethingWhichIsNoJsonWebToken() {
    assertInvalid("an-opaque-value", "json web signature");
  }

  @Test
  void shouldReturnNothingWithoutIdToken() {
    assertThat(verifier.verifyIdToken(null, NONCE)).isEmpty();
    assertThat(verifier.verifyIdToken("", NONCE)).isEmpty();
  }

  @Test
  void shouldNotVerifyWithoutKeySetUrl() {
    // no discovery url and no configured key set: nothing can be verified, so the
    // token is not used at all — but the login is not aborted either
    when(endpointResolver.resolve()).thenReturn(new Endpoints("a", "t", "u", null));

    assertThat(verifier.verifyIdToken(rsaSigned(claims(NONCE)), NONCE)).isEmpty();
  }

  @Test
  void shouldVerifyAccessToken() {
    String accessToken = rsaSigned("{\"iss\":\"" + ISSUER + "\",\"aud\":\"account\","
      + "\"exp\":" + expiry() + ",\"realm_access\":{\"roles\":[\"scmadmin\"]}}");

    Optional<JsonNode> claims = verifier.verifyAccessToken(accessToken);

    assertThat(claims).isPresent();
    assertThat(claims.get().get("realm_access").get("roles").get(0).asText()).isEqualTo("scmadmin");
  }

  @Test
  void shouldNotFailOnInvalidAccessTokenButReturnNothing() {
    // the access token is not the authentication proof, an anomaly costs the roles
    // instead of the login
    assertThat(verifier.verifyAccessToken(TestTokens.withBrokenSignature("RS256", KEY_ID, "{}"))).isEmpty();
    assertThat(verifier.verifyAccessToken(TestTokens.unsigned("{}"))).isEmpty();
    assertThat(verifier.verifyAccessToken("an-opaque-token")).isEmpty();
    assertThat(verifier.verifyAccessToken(null)).isEmpty();
  }

  @Test
  void shouldNotAcceptExpiredAccessToken() {
    String accessToken = rsaSigned("{\"iss\":\"" + ISSUER + "\",\"exp\":" + (NOW.getEpochSecond() - 3600) + "}");

    assertThat(verifier.verifyAccessToken(accessToken)).isEmpty();
  }

  @Test
  void shouldNotAcceptAccessTokenOfAnotherIssuer() {
    String accessToken = rsaSigned("{\"iss\":\"https://evil.hitchhiker.com\",\"exp\":" + expiry() + "}");

    assertThat(verifier.verifyAccessToken(accessToken)).isEmpty();
  }

  @Test
  void shouldAcceptAccessTokenWithoutAudienceOfThisClient() {
    // an access token is addressed to the resource server, not to this client
    String accessToken = rsaSigned("{\"iss\":\"" + ISSUER + "\",\"aud\":\"some-resource-server\",\"exp\":" + expiry() + "}");

    assertThat(verifier.verifyAccessToken(accessToken)).isPresent();
  }

  private void assertInvalid(String idToken, String messagePart) {
    assertThatThrownBy(() -> verifier.verifyIdToken(idToken, NONCE))
      .isInstanceOf(AuthenticationException.class)
      .hasMessageContaining(messagePart);
  }

  private String rsaSigned(String claims) {
    return TestTokens.signed("RS256", "SHA256withRSA", KEY_ID, claims, rsaKeyPair.getPrivate());
  }

  private String claims(String nonce) {
    return "{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\",\"sub\":\"trillian\","
      + "\"exp\":" + expiry() + ",\"iat\":" + NOW.getEpochSecond() + ",\"nonce\":\"" + nonce + "\"}";
  }

  private long expiry() {
    return NOW.getEpochSecond() + 300;
  }
}
