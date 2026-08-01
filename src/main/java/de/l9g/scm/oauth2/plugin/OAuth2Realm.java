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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import sonia.scm.plugin.Extension;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Extension
@Singleton
public class OAuth2Realm extends AuthenticatingRealm {

  private final AuthenticationInfoBuilder authenticationInfoBuilder;

  @Inject
  public OAuth2Realm(AuthenticationInfoBuilder authenticationInfoBuilder) {
    this.authenticationInfoBuilder = authenticationInfoBuilder;

    setAuthenticationTokenClass(OAuth2Token.class);
    setCredentialsMatcher(new AllowAllCredentialsMatcher());
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
    OAuth2Token oauth2Token = (OAuth2Token) token;
    return authenticationInfoBuilder.create(
      oauth2Token.getCredentials(), oauth2Token.getRedirectUri(), oauth2Token.getCodeVerifier()
    );
  }

}
