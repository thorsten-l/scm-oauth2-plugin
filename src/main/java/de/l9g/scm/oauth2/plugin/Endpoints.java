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
 *
 * <p>Immutable value object, always obtained from the {@link EndpointResolver} and
 * never created by callers.
 */
@Getter
public class Endpoints {

  private final String authorizationUrl;
  private final String tokenUrl;
  private final String userinfoUrl;
  private final String endSessionUrl;

  /**
   * Url of the json web key set, needed to verify the token signatures. From the
   * discovery document ({@code jwks_uri}) or from the manual configuration; may be
   * {@code null}, then no token is verified and none is used.
   */
  private final String jwksUrl;

  /**
   * Issuer of the identity provider, only known from a discovery document. If it is
   * set, the {@code iss} claim of a token has to match it.
   */
  private final String issuer;

  /**
   * The code challenge methods advertised by the discovery document. Empty, if
   * the endpoints were configured manually and the capabilities are unknown.
   */
  private final Set<String> codeChallengeMethods;

  /**
   * Constructor for manually configured endpoints, where neither the capabilities of
   * the provider nor its issuer are known.
   */
  public Endpoints(String authorizationUrl, String tokenUrl, String userinfoUrl, String endSessionUrl) {
    this(authorizationUrl, tokenUrl, userinfoUrl, endSessionUrl, null);
  }

  /**
   * Constructor for manually configured endpoints with a configured key set url.
   */
  public Endpoints(String authorizationUrl, String tokenUrl, String userinfoUrl, String endSessionUrl, String jwksUrl) {
    this(authorizationUrl, tokenUrl, userinfoUrl, endSessionUrl, jwksUrl, null, Set.of());
  }

  /**
   * Constructor for endpoints from a discovery document, which also names the issuer
   * and the supported code challenge methods.
   */
  public Endpoints(String authorizationUrl, String tokenUrl, String userinfoUrl, String endSessionUrl, String jwksUrl, String issuer, Set<String> codeChallengeMethods) {
    this.authorizationUrl = authorizationUrl;
    this.tokenUrl = tokenUrl;
    this.userinfoUrl = userinfoUrl;
    this.endSessionUrl = endSessionUrl;
    this.jwksUrl = jwksUrl;
    this.issuer = issuer;
    this.codeChallengeMethods = codeChallengeMethods == null ? Set.of() : codeChallengeMethods;
  }

  /**
   * The end session endpoint is the only optional one, therefore it is offered as
   * an optional in addition to the generated getter.
   *
   * @return end session endpoint, empty if the provider has none
   */
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
   *
   * @return {@code true} if the authorization request should contain a code challenge
   */
  public boolean supportsPkce() {
    return codeChallengeMethods.isEmpty() || codeChallengeMethods.contains(Pkce.METHOD);
  }
}
