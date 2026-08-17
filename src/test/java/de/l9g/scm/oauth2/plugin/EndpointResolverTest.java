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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests the two sources of the endpoints and the behaviour of the cache: manual
 * configuration, resolution from the discovery document, one request per hour and a
 * new request as soon as the cache expires or the discovery url changes.
 */
@ExtendWith(MockitoExtension.class)
class EndpointResolverTest {

  private static final String DISCOVERY_URL = "https://idp.hitchhiker.com/realms/main";

  @Mock
  private OAuth2Context context;

  @Mock
  private DiscoveryClient discoveryClient;

  @Test
  void shouldUseManuallyConfiguredEndpoints() {
    OAuth2Configuration configuration = new OAuth2Configuration();
    configuration.setAuthorizationUrl("https://idp.hitchhiker.com/auth");
    configuration.setTokenUrl("https://idp.hitchhiker.com/token");
    configuration.setUserinfoUrl("https://idp.hitchhiker.com/userinfo");
    configuration.setEndSessionUrl("https://idp.hitchhiker.com/logout");
    when(context.get()).thenReturn(configuration);

    EndpointResolver resolver = new EndpointResolver(context, discoveryClient);
    Endpoints endpoints = resolver.resolve();

    assertThat(endpoints.getAuthorizationUrl()).isEqualTo("https://idp.hitchhiker.com/auth");
    assertThat(endpoints.getTokenUrl()).isEqualTo("https://idp.hitchhiker.com/token");
    assertThat(endpoints.getUserinfoUrl()).isEqualTo("https://idp.hitchhiker.com/userinfo");
    assertThat(endpoints.getOptionalEndSessionUrl()).contains("https://idp.hitchhiker.com/logout");
    verifyNoInteractions(discoveryClient);
  }

  @Test
  void shouldResolveEndpointsFromDiscoveryDocument() {
    OAuth2Configuration configuration = new OAuth2Configuration();
    configuration.setDiscoveryUrl(DISCOVERY_URL);
    when(context.get()).thenReturn(configuration);

    Endpoints discovered = new Endpoints("a", "t", "u", "e");
    when(discoveryClient.fetch(DISCOVERY_URL)).thenReturn(discovered);

    EndpointResolver resolver = new EndpointResolver(context, discoveryClient);

    assertThat(resolver.resolve()).isSameAs(discovered);
  }

  @Test
  void shouldCacheDiscoveryDocument() {
    OAuth2Configuration configuration = new OAuth2Configuration();
    configuration.setDiscoveryUrl(DISCOVERY_URL);
    when(context.get()).thenReturn(configuration);
    when(discoveryClient.fetch(DISCOVERY_URL)).thenReturn(new Endpoints("a", "t", "u", null));

    EndpointResolver resolver = new EndpointResolver(context, discoveryClient);
    resolver.resolve();
    resolver.resolve();

    verify(discoveryClient, times(1)).fetch(DISCOVERY_URL);
  }

  @Test
  void shouldRefetchAfterCacheExpiration() {
    OAuth2Configuration configuration = new OAuth2Configuration();
    configuration.setDiscoveryUrl(DISCOVERY_URL);
    when(context.get()).thenReturn(configuration);
    when(discoveryClient.fetch(DISCOVERY_URL)).thenReturn(new Endpoints("a", "t", "u", null));

    MutableClock clock = new MutableClock(Instant.now());
    EndpointResolver resolver = new EndpointResolver(context, discoveryClient, clock);
    resolver.resolve();
    clock.advanceMinutes(61);
    resolver.resolve();

    verify(discoveryClient, times(2)).fetch(DISCOVERY_URL);
  }

  @Test
  void shouldRefetchAfterDiscoveryUrlChange() {
    OAuth2Configuration configuration = new OAuth2Configuration();
    configuration.setDiscoveryUrl(DISCOVERY_URL);
    when(context.get()).thenReturn(configuration);
    when(discoveryClient.fetch(DISCOVERY_URL)).thenReturn(new Endpoints("a", "t", "u", null));

    EndpointResolver resolver = new EndpointResolver(context, discoveryClient);
    resolver.resolve();

    String otherUrl = "https://other.hitchhiker.com/realms/main";
    configuration.setDiscoveryUrl(otherUrl);
    when(discoveryClient.fetch(otherUrl)).thenReturn(new Endpoints("a2", "t2", "u2", null));

    assertThat(resolver.resolve().getAuthorizationUrl()).isEqualTo("a2");
  }

  private static class MutableClock extends Clock {

    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    private void advanceMinutes(long minutes) {
      instant = instant.plusSeconds(minutes * 60L);
    }

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
      return instant;
    }
  }
}
