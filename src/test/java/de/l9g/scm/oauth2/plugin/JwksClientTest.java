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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.authc.AuthenticationException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests the parsing of a json web key set: rsa and elliptic curve keys are rebuilt
 * from their coordinates and are identical to the keys of the issuer, keys which
 * cannot be used are skipped instead of failing the whole set, and a document which
 * is no key set is rejected.
 */
class JwksClientTest {

  private static final String KEY_ID = "the-key";

  private final JwksClient client = new JwksClient(null, null, new ObjectMapper());
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void shouldReadRsaKey() throws IOException {
    KeyPair keyPair = TestTokens.rsaKeyPair();

    Optional<PublicKey> key = parse(TestTokens.jwks(KEY_ID, keyPair.getPublic())).find(KEY_ID, "RSA");

    assertThat(key).isPresent();
    // the rebuilt key has to be the very key of the issuer
    assertThat(key.get()).isEqualTo(keyPair.getPublic());
  }

  @Test
  void shouldReadEcKey() throws IOException {
    KeyPair keyPair = TestTokens.ecKeyPair();

    Optional<PublicKey> key = parse(TestTokens.jwks(KEY_ID, keyPair.getPublic())).find(KEY_ID, "EC");

    assertThat(key).isPresent();
    assertThat(key.get()).isEqualTo(keyPair.getPublic());
  }

  @Test
  void shouldNotReturnKeyOfAnotherType() throws IOException {
    KeyPair keyPair = TestTokens.rsaKeyPair();

    // an rsa key must never be handed out for an elliptic curve signature
    assertThat(parse(TestTokens.jwks(KEY_ID, keyPair.getPublic())).find(KEY_ID, "EC")).isEmpty();
  }

  @Test
  void shouldNotReturnKeyOfAnotherKeyId() throws IOException {
    KeyPair keyPair = TestTokens.rsaKeyPair();

    assertThat(parse(TestTokens.jwks(KEY_ID, keyPair.getPublic())).find("another-key", "RSA")).isEmpty();
  }

  @Test
  void shouldReturnKeyOfMatchingTypeIfTokenNamesNoKeyId() throws IOException {
    KeyPair keyPair = TestTokens.rsaKeyPair();

    assertThat(parse(TestTokens.jwks(KEY_ID, keyPair.getPublic())).find(null, "RSA")).isPresent();
  }

  @Test
  void shouldSkipEncryptionKeys() throws IOException {
    String jwks = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"enc\",\"kid\":\"" + KEY_ID + "\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}";

    assertThat(parse(jwks).isEmpty()).isTrue();
  }

  @Test
  void shouldSkipUnsupportedKeyTypesAndBrokenKeys() throws IOException {
    KeyPair keyPair = TestTokens.rsaKeyPair();
    String usable = TestTokens.jwks(KEY_ID, keyPair.getPublic());
    String broken = "{\"keys\":["
      + "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"unsupported\",\"x\":\"AQAB\"},"
      + "{\"kty\":\"RSA\",\"kid\":\"incomplete\"},"
      + "{\"kty\":\"EC\",\"crv\":\"P-192\",\"kid\":\"unsupported-curve\",\"x\":\"AQAB\",\"y\":\"AQAB\"},"
      + usable.substring(usable.indexOf('{', 1));

    JsonWebKeys keys = parse(broken);

    // the usable key survives, the others are skipped
    assertThat(keys.find(KEY_ID, "RSA")).isPresent();
    assertThat(keys.find("unsupported", "OKP")).isEmpty();
    assertThat(keys.find("incomplete", "RSA")).isEmpty();
  }

  @Test
  void shouldFailWithoutKeysArray() throws IOException {
    assertThatThrownBy(() -> parse("{\"something\":\"else\"}"))
      .isInstanceOf(AuthenticationException.class)
      .hasMessageContaining("keys array");
  }

  private JsonWebKeys parse(String jwks) throws IOException {
    return client.parse(objectMapper.readTree(jwks));
  }
}
