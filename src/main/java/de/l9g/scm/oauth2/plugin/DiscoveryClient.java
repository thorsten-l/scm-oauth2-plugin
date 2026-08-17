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
import org.apache.shiro.authc.AuthenticationException;
import sonia.scm.SCMContextProvider;
import sonia.scm.Stage;
import sonia.scm.net.ahc.AdvancedHttpClient;
import sonia.scm.net.ahc.AdvancedHttpResponse;
import sonia.scm.util.HttpUtil;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Fetches the OIDC discovery document ({@code .well-known/openid-configuration})
 * of the identity provider and extracts the endpoints from it.
 *
 * <p>Only the fields the plugin actually needs are read. Authorization, token and
 * userinfo endpoint are mandatory; the end session endpoint is optional (it only
 * exists if the provider supports RP-initiated logout), {@code jwks_uri} and
 * {@code issuer} are used to verify token signatures and the issuer claim, and
 * {@code code_challenge_methods_supported} decides whether pkce is used.
 *
 * <p>Called by the {@link EndpointResolver}, which also caches the result - this
 * class always performs a request.
 */
public class DiscoveryClient {

  private static final String WELL_KNOWN_PATH = ".well-known/openid-configuration";

  private final SCMContextProvider contextProvider;
  private final AdvancedHttpClient httpClient;
  private final ObjectMapper objectMapper;

  @Inject
  public DiscoveryClient(SCMContextProvider contextProvider, AdvancedHttpClient httpClient, ObjectMapper objectMapper) {
    this.contextProvider = contextProvider;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
  }

  /**
   * Fetches the discovery document and maps it to the endpoints.
   *
   * @param discoveryUrl issuer url or complete url of the document
   * @return the endpoints described by the document
   * @throws AuthenticationException if the document cannot be fetched, cannot be
   *         parsed or does not contain one of the required endpoints
   */
  public Endpoints fetch(String discoveryUrl) {
    JsonNode document = fetchDocument(normalizeDiscoveryUrl(discoveryUrl));
    return new Endpoints(
      requiredText(document, "authorization_endpoint"),
      requiredText(document, "token_endpoint"),
      requiredText(document, "userinfo_endpoint"),
      optionalText(document, "end_session_endpoint"),
      // jwks_uri is mandatory for an OIDC provider, but a plain OAuth2 provider may
      // not publish one; without it no token signature can be verified
      optionalText(document, "jwks_uri"),
      optionalText(document, "issuer"),
      textArray(document, "code_challenge_methods_supported")
    );
  }

  /**
   * Accepts the issuer base url as well as the complete discovery document url.
   * Both forms are commonly copied out of a provider ui, so the well known path
   * is appended only if it is not there yet.
   *
   * @param discoveryUrl configured url
   * @return url of the discovery document
   */
  static String normalizeDiscoveryUrl(String discoveryUrl) {
    if (discoveryUrl.contains("/.well-known/")) {
      return discoveryUrl;
    }
    return HttpUtil.append(discoveryUrl, WELL_KNOWN_PATH);
  }

  private JsonNode fetchDocument(String url) {
    AdvancedHttpResponse response;
    try {
      response = httpClient.get(url)
        .spanKind("OAuth2")
        .disableCertificateValidation(isDevelopmentStageActive())
        .request();
    } catch (IOException ex) {
      throw new AuthenticationException("failed to fetch oidc discovery document", ex);
    }

    int statusCode = response.getStatus();
    if (statusCode != HttpServletResponse.SC_OK) {
      throw new AuthenticationException("failed to fetch oidc discovery document, server returned status " + statusCode);
    }

    try {
      return objectMapper.readTree(response.contentAsString());
    } catch (IOException ex) {
      throw new AuthenticationException("failed to parse oidc discovery document", ex);
    }
  }

  private String requiredText(JsonNode document, String field) {
    String value = optionalText(document, field);
    if (value == null) {
      throw new AuthenticationException("oidc discovery document does not contain " + field);
    }
    return value;
  }

  private String optionalText(JsonNode document, String field) {
    JsonNode node = document.get(field);
    if (node == null || node.isNull()) {
      return null;
    }
    return node.asText();
  }

  private Set<String> textArray(JsonNode document, String field) {
    JsonNode node = document.get(field);
    if (node == null || !node.isArray()) {
      return Set.of();
    }
    Set<String> values = new LinkedHashSet<>();
    node.forEach(item -> values.add(item.asText()));
    return values;
  }

  private boolean isDevelopmentStageActive() {
    return contextProvider.getStage() == Stage.DEVELOPMENT;
  }
}
