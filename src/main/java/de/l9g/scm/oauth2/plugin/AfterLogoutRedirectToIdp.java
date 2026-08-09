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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.api.v2.resources.LogoutRedirection;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.plugin.Extension;
import sonia.scm.util.HttpUtil;

import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Optional;

import static java.util.Optional.empty;
import static java.util.Optional.of;

/**
 * Performs an RP-initiated logout at the identity provider, if the
 * configuration flag "ssoLogout" is set. The id token of the login is passed
 * as {@code id_token_hint} together with a {@code post_logout_redirect_uri},
 * so the identity provider can terminate the matching SSO session without a
 * confirmation prompt and redirect the browser back to SCM-Manager.
 */
@Extension
public class AfterLogoutRedirectToIdp implements LogoutRedirection {

  private static final Logger LOG = LoggerFactory.getLogger(AfterLogoutRedirectToIdp.class);

  private final OAuth2Context context;
  private final EndpointResolver endpointResolver;
  private final IdTokenStore idTokenStore;
  private final ScmConfiguration scmConfiguration;
  private final Provider<HttpServletRequest> requestProvider;
  private final ObjectMapper objectMapper;

  @Inject
  public AfterLogoutRedirectToIdp(OAuth2Context context, EndpointResolver endpointResolver, IdTokenStore idTokenStore, ScmConfiguration scmConfiguration, Provider<HttpServletRequest> requestProvider, ObjectMapper objectMapper) {
    this.context = context;
    this.endpointResolver = endpointResolver;
    this.idTokenStore = idTokenStore;
    this.scmConfiguration = scmConfiguration;
    this.requestProvider = requestProvider;
    this.objectMapper = objectMapper;
  }

  @Override
  public Optional<URI> afterLogoutRedirectTo() {
    OAuth2Configuration configuration = context.get();
    if (!configuration.isEnabled() || !configuration.isSsoLogout()) {
      return empty();
    }

    Optional<String> endSessionUrl = resolveEndSessionUrl();
    if (!endSessionUrl.isPresent()) {
      LOG.warn("sso logout is enabled, but no end session endpoint is available");
      return empty();
    }

    return of(URI.create(createLogoutUrl(endSessionUrl.get(), configuration)));
  }

  private Optional<String> resolveEndSessionUrl() {
    try {
      return endpointResolver.resolve().getOptionalEndSessionUrl();
    } catch (RuntimeException ex) {
      LOG.warn("failed to resolve end session endpoint", ex);
      return empty();
    }
  }

  private String createLogoutUrl(String endSessionUrl, OAuth2Configuration configuration) {
    StringBuilder url = new StringBuilder(endSessionUrl);
    char separator = endSessionUrl.contains("?") ? '&' : '?';

    if (!Strings.isNullOrEmpty(configuration.getClientId())) {
      url.append(separator).append("client_id=").append(HttpUtil.encode(configuration.getClientId()));
      separator = '&';
    }

    Optional<String> idToken = currentIdToken();
    if (idToken.isPresent()) {
      url.append(separator).append("id_token_hint=").append(HttpUtil.encode(idToken.get()));
      separator = '&';
    }

    String baseUrl = scmConfiguration.getBaseUrl();
    if (!Strings.isNullOrEmpty(baseUrl)) {
      url.append(separator).append("post_logout_redirect_uri=").append(HttpUtil.encode(baseUrl));
    }

    return url.toString();
  }

  private Optional<String> currentIdToken() {
    return currentPrincipal().flatMap(idTokenStore::remove);
  }

  /**
   * The logout resource of the core logs the subject out before this hook is
   * called, so the shiro subject usually has no principal anymore at this
   * point. As fallback the principal is read from the access token cookie,
   * which is still present on the logout request.
   */
  private Optional<String> currentPrincipal() {
    try {
      Subject subject = SecurityUtils.getSubject();
      PrincipalCollection principals = subject.getPrincipals();
      if (principals != null && principals.getPrimaryPrincipal() != null) {
        return of(principals.getPrimaryPrincipal().toString());
      }
    } catch (RuntimeException ex) {
      LOG.debug("could not determine principal from subject", ex);
    }
    return principalFromAccessTokenCookie();
  }

  private Optional<String> principalFromAccessTokenCookie() {
    try {
      HttpServletRequest request = requestProvider.get();
      Cookie[] cookies = request.getCookies();
      if (cookies == null) {
        return empty();
      }
      for (Cookie cookie : cookies) {
        if (HttpUtil.COOKIE_BEARER_AUTHENTICATION.equals(cookie.getName())) {
          return subjectFromJwt(cookie.getValue());
        }
      }
    } catch (RuntimeException ex) {
      LOG.debug("could not determine principal from access token cookie", ex);
    }
    return empty();
  }

  /**
   * Extracts the sub claim from the jwt payload. The signature is not
   * verified, because the value is only used as key for the id token store.
   */
  private Optional<String> subjectFromJwt(String jwt) {
    return JwtPayload.read(jwt, objectMapper)
      .map(payload -> payload.get("sub"))
      .filter(sub -> !sub.isNull())
      .map(JsonNode::asText);
  }
}
