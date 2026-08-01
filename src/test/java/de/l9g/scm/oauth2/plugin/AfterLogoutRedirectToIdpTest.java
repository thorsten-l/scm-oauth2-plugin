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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.util.HttpUtil;

import jakarta.inject.Provider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AfterLogoutRedirectToIdpTest {

  private static final String END_SESSION_URL = "https://idp.hitchhiker.com/logout";

  @Mock
  private OAuth2Context context;

  @Mock
  private EndpointResolver endpointResolver;

  @Mock
  private Provider<HttpServletRequest> requestProvider;

  @Mock
  private HttpServletRequest request;

  private final IdTokenStore idTokenStore = new IdTokenStore();
  private final ScmConfiguration scmConfiguration = new ScmConfiguration();
  private final OAuth2Configuration configuration = new OAuth2Configuration();

  private AfterLogoutRedirectToIdp logoutRedirection;

  @BeforeEach
  void setUpLogoutRedirection() {
    logoutRedirection = new AfterLogoutRedirectToIdp(
      context, endpointResolver, idTokenStore, scmConfiguration, requestProvider, new ObjectMapper()
    );
    lenient().when(context.get()).thenReturn(configuration);
    lenient().when(endpointResolver.resolve()).thenReturn(new Endpoints("a", "t", "u", END_SESSION_URL));
    configuration.setEnabled(true);
    configuration.setSsoLogout(true);
    configuration.setClientId("scm-client");
    scmConfiguration.setBaseUrl("https://scm.hitchhiker.com/scm");
  }

  @Test
  void shouldNotRedirectIfSsoLogoutIsDisabled() {
    configuration.setSsoLogout(false);

    assertThat(logoutRedirection.afterLogoutRedirectTo()).isEmpty();
  }

  @Test
  void shouldNotRedirectWithoutEndSessionEndpoint() {
    when(endpointResolver.resolve()).thenReturn(new Endpoints("a", "t", "u", null));

    assertThat(logoutRedirection.afterLogoutRedirectTo()).isEmpty();
  }

  @Test
  void shouldRedirectWithClientIdAndPostLogoutRedirectUriWithoutIdToken() {
    when(requestProvider.get()).thenReturn(request);
    when(request.getCookies()).thenReturn(null);

    Optional<URI> uri = logoutRedirection.afterLogoutRedirectTo();

    assertThat(uri).isPresent();
    String url = uri.get().toString();
    assertThat(url).startsWith(END_SESSION_URL);
    assertThat(url).contains("client_id=scm-client");
    assertThat(url).contains("post_logout_redirect_uri=" + HttpUtil.encode("https://scm.hitchhiker.com/scm"));
    assertThat(url).doesNotContain("id_token_hint");
  }

  @Test
  void shouldRedirectWithIdTokenHintFromAccessTokenCookie() {
    idTokenStore.put("trillian", "the-id-token");

    String payload = Base64.getUrlEncoder().withoutPadding()
      .encodeToString("{\"sub\":\"trillian\"}".getBytes(StandardCharsets.UTF_8));
    Cookie cookie = new Cookie(HttpUtil.COOKIE_BEARER_AUTHENTICATION, "header." + payload + ".signature");

    when(requestProvider.get()).thenReturn(request);
    when(request.getCookies()).thenReturn(new Cookie[]{cookie});

    Optional<URI> uri = logoutRedirection.afterLogoutRedirectTo();

    assertThat(uri).isPresent();
    String url = uri.get().toString();
    assertThat(url).contains("id_token_hint=the-id-token");
    assertThat(url).contains("client_id=scm-client");
    assertThat(url).contains("post_logout_redirect_uri=");

    // consumed on logout
    assertThat(idTokenStore.remove("trillian")).isEmpty();
  }
}
