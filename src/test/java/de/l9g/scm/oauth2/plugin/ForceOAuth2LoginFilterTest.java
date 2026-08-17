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

import org.apache.shiro.authc.AuthenticationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.security.AccessToken;
import sonia.scm.security.AccessTokenCookieIssuer;
import sonia.scm.security.AccessTokenResolver;
import sonia.scm.security.ShouldRequestPassChecker;
import sonia.scm.util.HttpUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests when the filter redirects and when it lets a request pass. The two
 * important cases: a request with a valid access token cookie passes (otherwise the
 * browser would loop between callback and identity provider), a forged cookie does
 * not. Requests of the web interface get a 401 instead of a redirect.
 */
@ExtendWith(MockitoExtension.class)
class ForceOAuth2LoginFilterTest {

  @Mock
  private OAuth2Context context;

  @Mock
  private AccessTokenCookieIssuer cookieIssuer;

  @Mock
  private ShouldRequestPassChecker requestPassChecker;

  @Mock
  private AccessTokenResolver accessTokenResolver;

  @Mock
  private AccessToken accessToken;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private FilterChain chain;

  private ForceOAuth2LoginFilter filter;

  private final OAuth2Configuration configuration = new OAuth2Configuration();

  @BeforeEach
  void setUpFilter() {
    filter = new ForceOAuth2LoginFilter(context, cookieIssuer, requestPassChecker, accessTokenResolver);
    lenient().when(context.get()).thenReturn(configuration);
    configuration.setEnabled(true);
    configuration.setForceLogin(true);
  }

  @Test
  void shouldRedirectUnauthenticatedBrowserRequest() throws Exception {
    when(request.getRequestURI()).thenReturn("/scm/repos");
    when(request.getContextPath()).thenReturn("/scm");

    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(anyString());
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void shouldPassRequestWithValidBearerTokenCookie() throws Exception {
    when(request.getRequestURI()).thenReturn("/scm/repos");
    when(request.getContextPath()).thenReturn("/scm");
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(HttpUtil.COOKIE_BEARER_AUTHENTICATION, "jwt")});
    when(accessTokenResolver.resolve(any())).thenReturn(accessToken);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
    verify(response, never()).sendRedirect(anyString());
  }

  @Test
  void shouldRedirectIfBearerTokenCookieIsForged() throws Exception {
    when(request.getRequestURI()).thenReturn("/scm/repos");
    when(request.getContextPath()).thenReturn("/scm");
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(HttpUtil.COOKIE_BEARER_AUTHENTICATION, "forged")});
    when(accessTokenResolver.resolve(any())).thenThrow(new AuthenticationException("invalid token"));

    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(anyString());
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void shouldPassIfForceLoginIsDisabled() throws Exception {
    configuration.setForceLogin(false);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void shouldPassOAuth2CallbackRequest() throws Exception {
    when(request.getRequestURI()).thenReturn("/scm/api/v2/oauth2/auth/callback");
    when(request.getContextPath()).thenReturn("/scm");

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void shouldPassIfRequestPassCheckerPasses() throws Exception {
    when(requestPassChecker.shouldPass(request)).thenReturn(true);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void shouldSendUnauthorizedForAjaxRequests() throws Exception {
    when(request.getRequestURI()).thenReturn("/scm/api/v2/repositories");
    when(request.getContextPath()).thenReturn("/scm");
    when(request.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");

    filter.doFilter(request, response, chain);

    verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
    verify(chain, never()).doFilter(request, response);
  }
}
