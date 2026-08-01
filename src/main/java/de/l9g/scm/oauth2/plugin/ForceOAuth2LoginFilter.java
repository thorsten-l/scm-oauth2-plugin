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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.Priority;
import sonia.scm.filter.Filters;
import sonia.scm.filter.WebElement;
import sonia.scm.security.AccessTokenCookieIssuer;
import sonia.scm.security.AccessTokenResolver;
import sonia.scm.security.BearerToken;
import sonia.scm.security.ShouldRequestPassChecker;
import sonia.scm.util.HttpUtil;
import sonia.scm.web.filter.HttpFilter;

import jakarta.inject.Inject;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Forces unauthenticated browser requests to the identity provider,
 * if the configuration flag "forceLogin" is set.
 */
@WebElement("/*")
@Priority(Filters.PRIORITY_POST_AUTHENTICATION)
public class ForceOAuth2LoginFilter extends HttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(ForceOAuth2LoginFilter.class);

  private final OAuth2Context context;
  private final AccessTokenCookieIssuer accessTokenCookieIssuer;
  private final ShouldRequestPassChecker requestPassChecker;
  private final AccessTokenResolver accessTokenResolver;

  @Inject
  public ForceOAuth2LoginFilter(OAuth2Context context, AccessTokenCookieIssuer accessTokenCookieIssuer, ShouldRequestPassChecker requestPassChecker, AccessTokenResolver accessTokenResolver) {
    this.context = context;
    this.accessTokenCookieIssuer = accessTokenCookieIssuer;
    this.requestPassChecker = requestPassChecker;
    this.accessTokenResolver = accessTokenResolver;
  }

  @Override
  protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    if (shouldPassThrough(request)) {
      chain.doFilter(request, response);
    } else if (isWebInterfaceRequest(request)) {
      sendUnauthorized(response);
    } else {
      redirectToIdentityProvider(request, response);
    }
  }

  private void redirectToIdentityProvider(HttpServletRequest request, HttpServletResponse response) throws IOException {
    accessTokenCookieIssuer.invalidate(request, response);
    response.sendRedirect(createLoginRedirect(request));
  }

  private String createLoginRedirect(HttpServletRequest request) {
    String from = request.getRequestURI().substring(request.getContextPath().length());
    if ("/login".equals(from) && !Strings.isNullOrEmpty(request.getParameter("from"))) {
      from = request.getParameter("from");
    }
    return request.getContextPath() + "/api/" + OAuth2AuthenticationResource.PATH + "?from=" + HttpUtil.encode(from);
  }

  private void sendUnauthorized(HttpServletResponse response) throws IOException {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }

  private boolean isWebInterfaceRequest(HttpServletRequest request) {
    return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
  }

  private boolean shouldPassThrough(HttpServletRequest request) {
    return requestPassChecker.shouldPass(request)
      || isForceLoginDisabled()
      || isOAuth2Request(request)
      || hasValidAccessTokenCookie(request);
  }

  /**
   * SCM-Manager authenticates requests only below /api and /repo, so on ui and
   * asset paths the subject is never authenticated and the pass checker fails
   * even for logged in users. Requests carrying a valid access token cookie are
   * therefore let through, otherwise the browser would loop between callback and
   * identity provider. The token is verified here, so a fabricated cookie does
   * not bypass the forced login.
   */
  private boolean hasValidAccessTokenCookie(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return false;
    }
    for (Cookie cookie : cookies) {
      if (HttpUtil.COOKIE_BEARER_AUTHENTICATION.equals(cookie.getName()) && isValidAccessToken(cookie.getValue())) {
        return true;
      }
    }
    return false;
  }

  private boolean isValidAccessToken(String token) {
    if (Strings.isNullOrEmpty(token)) {
      return false;
    }
    try {
      return accessTokenResolver.resolve(BearerToken.valueOf(token)) != null;
    } catch (RuntimeException ex) {
      LOG.debug("request contains an access token cookie which could not be resolved", ex);
      return false;
    }
  }

  private boolean isForceLoginDisabled() {
    OAuth2Configuration configuration = context.get();
    return !configuration.isEnabled() || !configuration.isForceLogin();
  }

  private boolean isOAuth2Request(HttpServletRequest request) {
    return request.getRequestURI().startsWith(request.getContextPath() + "/api/" + OAuth2AuthenticationResource.PATH);
  }

}
