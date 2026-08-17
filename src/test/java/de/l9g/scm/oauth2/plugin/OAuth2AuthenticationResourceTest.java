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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests of the two endpoints, with the emphasis on the security properties of the
 * flow: the state has to match the state cookie of the browser, an unknown or
 * missing state is rejected, a state cannot be used twice, the redirect target has
 * to stay inside this instance, the pkce challenge is only sent if the provider
 * supports it, and neither an error of the identity provider nor an internal
 * authentication failure is reflected to the caller.
 */
@ExtendWith(MockitoExtension.class)
class OAuth2AuthenticationResourceTest {

  private static final String STATE = "the-state";
  private static final String VERIFIER = "the-code-verifier";
  private static final String NONCE = "the-nonce";

  private static final AuthorizationRequest PENDING = new AuthorizationRequest(STATE, VERIFIER, NONCE, "/repos");

  @Mock
  private OAuth2Context context;

  @Mock
  private EndpointResolver endpointResolver;

  @Mock
  private StateStore stateStore;

  @Mock
  private LoginHandler loginHandler;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  private final OAuth2Configuration configuration = new OAuth2Configuration();

  private OAuth2AuthenticationResource resource;

  @BeforeEach
  void setUpResource() {
    resource = new OAuth2AuthenticationResource(context, endpointResolver, stateStore, loginHandler);
    lenient().when(context.get()).thenReturn(configuration);
    lenient().when(request.getContextPath()).thenReturn("/scm");
    configuration.setEnabled(true);
    configuration.setClientId("scm-client");
  }

  @Test
  void shouldNotLoginIfStateCookieIsMissing() {
    when(request.getCookies()).thenReturn(null);

    Response result = resource.callback(request, response, "code", STATE, null, null);

    assertThat(result.getStatus()).isEqualTo(401);
    verify(stateStore, never()).consume(any());
    verify(loginHandler, never()).login(any(), any(), any());
  }

  @Test
  void shouldNotLoginIfStateCookieDoesNotMatchStateParameter() {
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(StateCookie.NAME, "state-of-another-browser")});

    Response result = resource.callback(request, response, "code", STATE, null, null);

    assertThat(result.getStatus()).isEqualTo(401);
    verify(stateStore, never()).consume(any());
    verify(loginHandler, never()).login(any(), any(), any());
  }

  @Test
  void shouldNotLoginWithoutStateParameter() {
    lenient().when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(StateCookie.NAME, STATE)});

    Response result = resource.callback(request, response, "code", null, null, null);

    assertThat(result.getStatus()).isEqualTo(401);
    verify(loginHandler, never()).login(any(), any(), any());
  }

  @Test
  void shouldNotLoginWithUnknownState() {
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(StateCookie.NAME, STATE)});
    when(stateStore.consume(STATE)).thenReturn(Optional.empty());

    Response result = resource.callback(request, response, "code", STATE, null, null);

    assertThat(result.getStatus()).isEqualTo(401);
    verify(loginHandler, never()).login(any(), any(), any());
  }

  @Test
  void shouldNotReflectErrorOfIdentityProvider() {
    Response result = resource.callback(request, response, null, STATE, "<img src=x onerror=alert(1)>", "desc");

    assertThat(result.getStatus()).isEqualTo(401);
    assertThat(result.getEntity().toString()).doesNotContain("<img");
    verify(loginHandler, never()).login(any(), any(), any());
  }

  @Test
  void shouldLoginIfStateMatchesTheStateCookie() {
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(StateCookie.NAME, STATE)});
    when(stateStore.consume(STATE)).thenReturn(Optional.of(PENDING));
    mockRequestUrl();

    Response result = resource.callback(request, response, "the-code", STATE, null, null);

    assertThat(result.getStatus()).isEqualTo(303);
    assertThat(result.getLocation().toString()).isEqualTo("http://scm.hitchhiker.com/scm/repos");
    verify(loginHandler).login(any(), any(), any());
    // the state cookie is consumed and cleared afterwards
    assertThat(result.getHeaderString(HttpHeaders.SET_COOKIE)).contains(StateCookie.NAME + "=;", "Max-Age=0");
  }

  @Test
  void shouldSetStateCookieOnLogin() {
    configuration.setScopes("openid");
    when(stateStore.create("/repos")).thenReturn(PENDING);
    when(endpointResolver.resolve()).thenReturn(
      new Endpoints("https://idp.hitchhiker.com/auth", "t", "u", null)
    );
    mockRequestUrl();

    Response result = resource.login(request, "/repos");

    assertThat(result.getStatus()).isEqualTo(303);
    assertThat(result.getLocation().toString()).contains("state=" + STATE);

    String cookie = result.getHeaderString(HttpHeaders.SET_COOKIE);
    assertThat(cookie)
      .contains(StateCookie.NAME + "=" + STATE)
      .contains("Path=/scm")
      .contains("HttpOnly")
      .contains("SameSite=Lax");
  }

  @Test
  void shouldMarkStateCookieAsSecureForHttps() {
    when(stateStore.create(any())).thenReturn(PENDING);
    when(endpointResolver.resolve()).thenReturn(new Endpoints("https://idp.hitchhiker.com/auth", "t", "u", null));
    mockRequestUrl();
    when(request.isSecure()).thenReturn(true);

    Response result = resource.login(request, "/");

    assertThat(result.getHeaderString(HttpHeaders.SET_COOKIE)).contains("Secure");
  }

  @Test
  void shouldNotRedirectToAnotherHost() {
    when(stateStore.create("/")).thenReturn(PENDING);
    when(endpointResolver.resolve()).thenReturn(new Endpoints("https://idp.hitchhiker.com/auth", "t", "u", null));
    mockRequestUrl();

    // protocol relative url must not be used as redirect target
    resource.login(request, "//evil.hitchhiker.com");

    verify(stateStore).create("/");
  }

  @Test
  void shouldSendNonceWithTheAuthorizationRequest() {
    when(stateStore.create(any())).thenReturn(PENDING);
    when(endpointResolver.resolve()).thenReturn(new Endpoints("https://idp.hitchhiker.com/auth", "t", "u", null));
    mockRequestUrl();

    Response result = resource.login(request, "/");

    // the identity provider echoes the nonce into the id token
    assertThat(result.getLocation().toString()).contains("nonce=" + NONCE);
  }

  @Test
  void shouldPassNonceOfTheAuthorizationRequestToTheRealm() {
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(StateCookie.NAME, STATE)});
    when(stateStore.consume(STATE)).thenReturn(Optional.of(PENDING));
    mockRequestUrl();

    resource.callback(request, response, "the-code", STATE, null, null);

    ArgumentCaptor<OAuth2Token> captor = ArgumentCaptor.forClass(OAuth2Token.class);
    verify(loginHandler).login(any(), any(), captor.capture());
    assertThat(captor.getValue().getNonce()).isEqualTo(NONCE);
  }

  @Test
  void shouldSendPkceChallenge() {
    when(stateStore.create(any())).thenReturn(PENDING);
    when(endpointResolver.resolve()).thenReturn(
      new Endpoints("https://idp.hitchhiker.com/auth", "t", "u", null, null, null, Set.of("plain", "S256"))
    );
    mockRequestUrl();

    String location = resource.login(request, "/").getLocation().toString();

    assertThat(location)
      .contains("code_challenge_method=S256")
      .contains("code_challenge=" + Pkce.createChallenge(VERIFIER))
      // the verifier itself must never leave the server
      .doesNotContain(VERIFIER);
  }

  @Test
  void shouldNotSendPkceChallengeIfProviderDoesNotSupportIt() {
    when(stateStore.create(any())).thenReturn(PENDING);
    when(endpointResolver.resolve()).thenReturn(
      new Endpoints("https://idp.hitchhiker.com/auth", "t", "u", null, null, null, Set.of("plain"))
    );
    mockRequestUrl();

    String location = resource.login(request, "/").getLocation().toString();

    assertThat(location).doesNotContain("code_challenge");
  }

  @Test
  void shouldPassCodeVerifierOfTheAuthorizationRequestToTheRealm() {
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(StateCookie.NAME, STATE)});
    when(stateStore.consume(STATE)).thenReturn(Optional.of(PENDING));
    mockRequestUrl();

    resource.callback(request, response, "the-code", STATE, null, null);

    ArgumentCaptor<OAuth2Token> captor = ArgumentCaptor.forClass(OAuth2Token.class);
    verify(loginHandler).login(any(), any(), captor.capture());
    assertThat(captor.getValue().getCodeVerifier()).isEqualTo(VERIFIER);
  }

  @Test
  void shouldNotLeakInternalsIfAuthenticationFails() {
    when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(StateCookie.NAME, STATE)});
    when(stateStore.consume(STATE)).thenReturn(Optional.of(PENDING));
    mockRequestUrl();
    doThrow(new AuthenticationException("token of type class de.l9g.internal could not be authenticated by any realm"))
      .when(loginHandler).login(any(), any(), any());

    Response result = resource.callback(request, response, "the-code", STATE, null, null);

    assertThat(result.getStatus()).isEqualTo(401);
    assertThat(result.getEntity().toString()).isEqualTo("authentication failed").doesNotContain("de.l9g");
  }

  @Test
  void shouldReturnNotFoundIfDisabled() {
    configuration.setEnabled(false);

    Response result = resource.login(request, "/");

    assertThat(result.getStatus()).isEqualTo(404);
    verify(stateStore, never()).create(any());
  }

  private void mockRequestUrl() {
    lenient().when(request.getRequestURL())
      .thenReturn(new StringBuffer("http://scm.hitchhiker.com/scm/api/v2/oauth2/auth/callback"));
    lenient().when(request.getRequestURI()).thenReturn("/scm/api/v2/oauth2/auth/callback");
    lenient().when(request.getScheme()).thenReturn("http");
    lenient().when(request.getServerName()).thenReturn("scm.hitchhiker.com");
    lenient().when(request.getServerPort()).thenReturn(80);
    lenient().when(request.getHeader(any())).thenReturn(null);
  }
}
