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
 *
 * <p>Created by the callback of the {@link OAuth2AuthenticationResource} and passed
 * to {@code subject.login}, from where shiro routes it to the
 * {@link OAuth2Realm}.
 */
public final class OAuth2Token implements AuthenticationToken {

  private final String code;
  private final String redirectUri;
  private final String codeVerifier;
  private final String nonce;

  private OAuth2Token(String code, String redirectUri, String codeVerifier, String nonce) {
    this.code = code;
    this.redirectUri = redirectUri;
    this.codeVerifier = codeVerifier;
    this.nonce = nonce;
  }

  /**
   * @return the authorization code, the only credential of this flow
   */
  @Override
  public String getCredentials() {
    return code;
  }

  /**
   * @return callback url of the authorization request, it has to be sent again
   *         when the code is redeemed
   */
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

  /**
   * The nonce of the authorization request, the id token has to carry the same value.
   * May be {@code null} for a request which was created without one.
   */
  public String getNonce() {
    return nonce;
  }

  /**
   * The principal is only known after the code has been exchanged and the claims
   * have been read, so this token cannot provide one.
   *
   * @return never returns
   * @throws UnsupportedOperationException always
   */
  @Override
  public Object getPrincipal() {
    throw new UnsupportedOperationException("OAuth2Token has no principal, it provides only credentials");
  }

  /**
   * Factory for a flow without pkce and without nonce.
   */
  public static OAuth2Token valueOf(String code, String redirectUri) {
    return valueOf(code, redirectUri, null, null);
  }

  /**
   * Factory with validation of the mandatory values, so a broken token cannot
   * reach the realm.
   *
   * @param code         authorization code, mandatory
   * @param redirectUri  callback url of the authorization request, mandatory
   * @param codeVerifier pkce verifier, optional
   * @param nonce        nonce of the authorization request, optional
   * @return the token for {@code subject.login}
   * @throws IllegalArgumentException if code or redirect uri are missing
   */
  public static OAuth2Token valueOf(String code, String redirectUri, String codeVerifier, String nonce) {
    checkArgument(!Strings.isNullOrEmpty(code), "code is null or empty");
    checkArgument(!Strings.isNullOrEmpty(redirectUri), "redirectUri is null or empty");
    return new OAuth2Token(code, redirectUri, codeVerifier, nonce);
  }
}
