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
import lombok.Getter;

import java.util.Optional;
import java.util.Set;

/**
 * The resolved endpoints of the identity provider, either taken from the
 * manual configuration or from the OIDC discovery document.
 */
@Getter
public class Endpoints {

  private final String authorizationUrl;
  private final String tokenUrl;
  private final String userinfoUrl;
  private final String endSessionUrl;

  /**
   * The code challenge methods advertised by the discovery document. Empty, if
   * the endpoints were configured manually and the capabilities are unknown.
   */
  private final Set<String> codeChallengeMethods;

  public Endpoints(String authorizationUrl, String tokenUrl, String userinfoUrl, String endSessionUrl) {
    this(authorizationUrl, tokenUrl, userinfoUrl, endSessionUrl, Set.of());
  }

  public Endpoints(String authorizationUrl, String tokenUrl, String userinfoUrl, String endSessionUrl, Set<String> codeChallengeMethods) {
    this.authorizationUrl = authorizationUrl;
    this.tokenUrl = tokenUrl;
    this.userinfoUrl = userinfoUrl;
    this.endSessionUrl = endSessionUrl;
    this.codeChallengeMethods = codeChallengeMethods == null ? Set.of() : codeChallengeMethods;
  }

  public Optional<String> getOptionalEndSessionUrl() {
    if (Strings.isNullOrEmpty(endSessionUrl)) {
      return Optional.empty();
    }
    return Optional.of(endSessionUrl);
  }

  /**
   * PKCE is used unless the identity provider explicitly states that it does
   * not support it. Providers which do not know the parameters have to ignore
   * them according to rfc 6749.
   */
  public boolean supportsPkce() {
    return codeChallengeMethods.isEmpty() || codeChallengeMethods.contains(Pkce.METHOD);
  }
}
