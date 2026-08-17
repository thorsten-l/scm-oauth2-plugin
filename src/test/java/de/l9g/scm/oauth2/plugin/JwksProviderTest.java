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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests the caching of the key set: one request per hour, a new request after the
 * cache expired or the url changed, and — the case of a key rotation at the identity
 * provider — a new request when a token names a key the cached set does not contain.
 * The refresh is rate limited, so an unknown key id cannot be used to trigger a
 * request per token.
 */
@ExtendWith(MockitoExtension.class)
class JwksProviderTest {

  private static final String JWKS_URL = "https://idp.hitchhiker.com/certs";
  private static final Instant NOW = Instant.parse("2026-08-17T12:00:00Z");

  @Mock
  private JwksClient client;

  private Instant now = NOW;

  private final KeyPair keyPair = TestTokens.rsaKeyPair();

  private JwksProvider provider;

  /**
   * The mocks are injected after the test instance was created, so the provider is
   * built here. Its clock follows the {@link #now} field, which lets a test move time.
   */
  @BeforeEach
  void setUpProvider() {
    provider = new JwksProvider(client, movingClock());
  }

  @Test
  void shouldFetchAndCacheTheKeySet() {
    when(client.fetch(JWKS_URL)).thenReturn(keys("the-key"));

    assertThat(provider.resolve(JWKS_URL, "the-key", "RSA")).isPresent();
    assertThat(provider.resolve(JWKS_URL, "the-key", "RSA")).isPresent();

    verify(client, times(1)).fetch(JWKS_URL);
  }

  @Test
  void shouldFetchAgainAfterCacheExpiration() {
    when(client.fetch(JWKS_URL)).thenReturn(keys("the-key"));

    assertThat(provider.resolve(JWKS_URL, "the-key", "RSA")).isPresent();
    now = NOW.plus(Duration.ofHours(2));
    assertThat(provider.resolve(JWKS_URL, "the-key", "RSA")).isPresent();

    verify(client, times(2)).fetch(JWKS_URL);
  }

  @Test
  void shouldFetchAgainAfterUrlChange() {
    String otherUrl = "https://another-idp.hitchhiker.com/certs";
    when(client.fetch(JWKS_URL)).thenReturn(keys("the-key"));
    when(client.fetch(otherUrl)).thenReturn(keys("the-key"));

    provider.resolve(JWKS_URL, "the-key", "RSA");
    provider.resolve(otherUrl, "the-key", "RSA");

    verify(client).fetch(JWKS_URL);
    verify(client).fetch(otherUrl);
  }

  @Test
  void shouldFetchAgainForAnUnknownKeyId() {
    when(client.fetch(JWKS_URL)).thenReturn(keys("the-old-key"), keys("the-new-key"));

    // first login fills the cache
    assertThat(provider.resolve(JWKS_URL, "the-old-key", "RSA")).isPresent();

    // the provider rotated its key; the rate limit has to be over for the refresh
    now = NOW.plus(Duration.ofMinutes(2));
    assertThat(provider.resolve(JWKS_URL, "the-new-key", "RSA")).isPresent();

    verify(client, times(2)).fetch(JWKS_URL);
  }

  @Test
  void shouldNotFetchAgainWithinTheRateLimit() {
    when(client.fetch(JWKS_URL)).thenReturn(keys("the-key"));

    provider.resolve(JWKS_URL, "the-key", "RSA");
    // an unknown key id must not trigger a request per token
    assertThat(provider.resolve(JWKS_URL, "made-up-key", "RSA")).isEmpty();
    assertThat(provider.resolve(JWKS_URL, "made-up-key", "RSA")).isEmpty();

    verify(client, times(1)).fetch(JWKS_URL);
  }

  private Clock movingClock() {
    return new Clock() {
      @Override
      public ZoneOffset getZone() {
        return ZoneOffset.UTC;
      }

      @Override
      public Clock withZone(java.time.ZoneId zone) {
        return this;
      }

      @Override
      public Instant instant() {
        return now;
      }
    };
  }

  private JsonWebKeys keys(String keyId) {
    return JsonWebKeys.of(List.of(new JsonWebKeys.Entry(keyId, "RSA", keyPair.getPublic())));
  }
}
