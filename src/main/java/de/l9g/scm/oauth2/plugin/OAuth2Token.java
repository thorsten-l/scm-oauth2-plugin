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
import org.apache.shiro.authc.AuthenticationToken;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Shiro authentication token which carries the authorization code received
 * from the identity provider and the redirect uri which was used to obtain it.
 * The redirect uri is required again for the code exchange at the token endpoint.
 */
public final class OAuth2Token implements AuthenticationToken {

  private final String code;
  private final String redirectUri;
  private final String codeVerifier;

  private OAuth2Token(String code, String redirectUri, String codeVerifier) {
    this.code = code;
    this.redirectUri = redirectUri;
    this.codeVerifier = codeVerifier;
  }

  @Override
  public String getCredentials() {
    return code;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  /**
   * The pkce verifier of the authorization request, may be {@code null} if the
   * identity provider does not support pkce.
   */
  public String getCodeVerifier() {
    return codeVerifier;
  }

  @Override
  public Object getPrincipal() {
    throw new UnsupportedOperationException("OAuth2Token has no principal, it provides only credentials");
  }

  public static OAuth2Token valueOf(String code, String redirectUri) {
    return valueOf(code, redirectUri, null);
  }

  public static OAuth2Token valueOf(String code, String redirectUri, String codeVerifier) {
    checkArgument(!Strings.isNullOrEmpty(code), "code is null or empty");
    checkArgument(!Strings.isNullOrEmpty(redirectUri), "redirectUri is null or empty");
    return new OAuth2Token(code, redirectUri, codeVerifier);
  }
}
