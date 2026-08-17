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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the normalization of the discovery url: the well known path is appended to an
 * issuer url with and without a trailing slash, and a complete document url is kept
 * as it is.
 */
class DiscoveryClientTest {

  @Test
  void shouldAppendWellKnownPathToIssuerUrl() {
    assertThat(DiscoveryClient.normalizeDiscoveryUrl("https://idp.hitchhiker.com/realms/main"))
      .isEqualTo("https://idp.hitchhiker.com/realms/main/.well-known/openid-configuration");
  }

  @Test
  void shouldAppendWellKnownPathToIssuerUrlWithTrailingSlash() {
    assertThat(DiscoveryClient.normalizeDiscoveryUrl("https://idp.hitchhiker.com/realms/main/"))
      .isEqualTo("https://idp.hitchhiker.com/realms/main/.well-known/openid-configuration");
  }

  @Test
  void shouldKeepCompleteDiscoveryUrl() {
    String url = "https://idp.hitchhiker.com/realms/main/.well-known/openid-configuration";
    assertThat(DiscoveryClient.normalizeDiscoveryUrl(url)).isEqualTo(url);
  }
}
