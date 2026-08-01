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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import sonia.scm.security.AccessToken;
import sonia.scm.security.AccessTokenBuilder;
import sonia.scm.security.AccessTokenBuilderFactory;
import sonia.scm.security.AccessTokenCookieIssuer;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class LoginHandler {

  private final AccessTokenBuilderFactory tokenBuilderFactory;
  private final AccessTokenCookieIssuer cookieIssuer;

  @Inject
  public LoginHandler(AccessTokenBuilderFactory tokenBuilderFactory, AccessTokenCookieIssuer cookieIssuer) {
    this.tokenBuilderFactory = tokenBuilderFactory;
    this.cookieIssuer = cookieIssuer;
  }

  public void login(HttpServletRequest request, HttpServletResponse response, OAuth2Token token) {
    Subject subject = SecurityUtils.getSubject();
    subject.login(token);

    PrincipalCollection principals = subject.getPrincipals();

    AccessTokenBuilder accessTokenBuilder = tokenBuilderFactory.create();
    accessTokenBuilder.subject(principals.getPrimaryPrincipal().toString());

    AccessToken accessToken = accessTokenBuilder.build();
    cookieIssuer.authenticate(request, response, accessToken);
  }
}
