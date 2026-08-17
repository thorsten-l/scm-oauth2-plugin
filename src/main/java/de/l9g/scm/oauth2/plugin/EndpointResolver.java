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

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Clock;

/**
 * Resolves the identity provider endpoints. If a discovery url is configured,
 * the endpoints are taken from the OIDC discovery document (cached for one hour),
 * otherwise the manually configured endpoints are used.
 *
 * <p>The cache is a single entry which also stores the url it was fetched for, so
 * changing the discovery url in the administration ui invalidates it implicitly -
 * no event listener is needed.
 *
 * <p>Singleton, otherwise every injection point would have its own cache. The
 * {@code volatile} field is enough for the concurrency happening here: two
 * parallel logins may fetch the document twice, but they cannot see a
 * half initialized entry.
 */
@Singleton
public class EndpointResolver {

  private static final long CACHE_TTL_IN_MILLIS = 60L * 60L * 1000L;

  private final OAuth2Context context;
  private final DiscoveryClient discoveryClient;
  private final Clock clock;

  private volatile CacheEntry cache;

  @Inject
  public EndpointResolver(OAuth2Context context, DiscoveryClient discoveryClient) {
    this(context, discoveryClient, Clock.systemUTC());
  }

  /**
   * Constructor for the tests, which need a controllable clock to verify the cache
   * expiry.
   */
  EndpointResolver(OAuth2Context context, DiscoveryClient discoveryClient, Clock clock) {
    this.context = context;
    this.discoveryClient = discoveryClient;
    this.clock = clock;
  }

  /**
   * Returns the endpoints to use for the current configuration.
   *
   * @return resolved endpoints, from the cache if it is still valid
   * @throws org.apache.shiro.authc.AuthenticationException if a discovery url is
   *         configured but the document cannot be fetched
   */
  public Endpoints resolve() {
    OAuth2Configuration configuration = context.get();

    String discoveryUrl = configuration.getDiscoveryUrl();
    if (Strings.isNullOrEmpty(discoveryUrl)) {
      // manual configuration: the capabilities and the issuer of the provider are
      // unknown, the key set url has to be configured explicitly
      return new Endpoints(
        configuration.getAuthorizationUrl(),
        configuration.getTokenUrl(),
        configuration.getUserinfoUrl(),
        configuration.getEndSessionUrl(),
        configuration.getJwksUrl()
      );
    }

    CacheEntry cached = cache;
    if (cached != null && cached.isValidFor(discoveryUrl, clock.millis())) {
      return cached.endpoints;
    }

    Endpoints endpoints = discoveryClient.fetch(discoveryUrl);
    cache = new CacheEntry(discoveryUrl, clock.millis(), endpoints);
    return endpoints;
  }

  /**
   * Immutable cache entry. It remembers the url it belongs to, so a configuration
   * change cannot be served from a stale cache.
   */
  private static class CacheEntry {
    private final String discoveryUrl;
    private final long fetchedAt;
    private final Endpoints endpoints;

    private CacheEntry(String discoveryUrl, long fetchedAt, Endpoints endpoints) {
      this.discoveryUrl = discoveryUrl;
      this.fetchedAt = fetchedAt;
      this.endpoints = endpoints;
    }

    private boolean isValidFor(String url, long now) {
      return discoveryUrl.equals(url) && now - fetchedAt < CACHE_TTL_IN_MILLIS;
    }
  }
}
