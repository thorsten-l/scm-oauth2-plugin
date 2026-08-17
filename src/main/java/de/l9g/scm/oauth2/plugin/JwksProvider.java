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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.security.PublicKey;
import java.time.Clock;
import java.util.Optional;

/**
 * Caches the json web key set of the identity provider and resolves the key of a
 * signature.
 *
 * <p>Two mechanisms keep the cache correct without a background task:
 *
 * <ul>
 *   <li>an entry expires after one hour, and it remembers the url it was fetched
 *       for, so a configuration change invalidates it implicitly</li>
 *   <li>if a token names a key id which the cached set does not contain, the set is
 *       fetched again — this is what happens after a key rotation at the identity
 *       provider. To keep an attacker from triggering a request per token, the
 *       refresh happens at most once per minute.</li>
 * </ul>
 *
 * <p>Singleton, otherwise every injection point would keep its own cache.
 *
 * @see JwksClient
 * @see TokenVerifier
 */
@Singleton
public class JwksProvider {

  private static final Logger LOG = LoggerFactory.getLogger(JwksProvider.class);

  private static final long CACHE_TTL_IN_MILLIS = 60L * 60L * 1000L;
  private static final long MIN_REFRESH_INTERVAL_IN_MILLIS = 60L * 1000L;

  private final JwksClient client;
  private final Clock clock;

  private volatile CacheEntry cache;
  private volatile long lastRefresh;

  @Inject
  public JwksProvider(JwksClient client) {
    this(client, Clock.systemUTC());
  }

  JwksProvider(JwksClient client, Clock clock) {
    this.client = client;
    this.clock = clock;
  }

  /**
   * Resolves the key which belongs to a signature.
   *
   * @param jwksUrl url of the key set
   * @param keyId   value of the {@code kid} header of the token, may be {@code null}
   * @param keyType required key type, {@code RSA} or {@code EC}
   * @return the key, empty if the provider does not publish a matching one
   * @throws org.apache.shiro.authc.AuthenticationException if the key set cannot be
   *         fetched or parsed
   */
  Optional<PublicKey> resolve(String jwksUrl, String keyId, String keyType) {
    JsonWebKeys keys = keys(jwksUrl);

    Optional<PublicKey> key = keys.find(keyId, keyType);
    if (key.isPresent()) {
      return key;
    }

    if (!mayRefresh()) {
      return Optional.empty();
    }

    LOG.debug("key '{}' is unknown, fetching the json web key set again", keyId);
    return refresh(jwksUrl).find(keyId, keyType);
  }

  private JsonWebKeys keys(String jwksUrl) {
    CacheEntry cached = cache;
    if (cached != null && cached.isValidFor(jwksUrl, clock.millis())) {
      return cached.keys;
    }
    return refresh(jwksUrl);
  }

  private JsonWebKeys refresh(String jwksUrl) {
    JsonWebKeys keys = client.fetch(jwksUrl);
    long now = clock.millis();
    cache = new CacheEntry(jwksUrl, now, keys);
    lastRefresh = now;
    return keys;
  }

  private boolean mayRefresh() {
    return clock.millis() - lastRefresh >= MIN_REFRESH_INTERVAL_IN_MILLIS;
  }

  /**
   * Immutable cache entry which remembers the url it belongs to.
   */
  private static class CacheEntry {

    private final String jwksUrl;
    private final long fetchedAt;
    private final JsonWebKeys keys;

    private CacheEntry(String jwksUrl, long fetchedAt, JsonWebKeys keys) {
      this.jwksUrl = jwksUrl;
      this.fetchedAt = fetchedAt;
      this.keys = keys;
    }

    private boolean isValidFor(String url, long now) {
      return jwksUrl.equals(url) && now - fetchedAt < CACHE_TTL_IN_MILLIS;
    }
  }
}
