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
import org.apache.shiro.authc.AuthenticationException;
import sonia.scm.SCMContextProvider;
import sonia.scm.Stage;
import sonia.scm.net.ahc.AdvancedHttpClient;
import sonia.scm.net.ahc.AdvancedHttpResponse;
import sonia.scm.net.ahc.FormContentBuilder;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Client for the OAuth2/OIDC endpoints of the identity provider.
 * Exchanges an authorization code for tokens and reads the
 * user claims from the userinfo endpoint.
 */
public class OAuth2RestClient {

  private final SCMContextProvider contextProvider;
  private final AdvancedHttpClient httpClient;
  private final OAuth2Context context;
  private final EndpointResolver endpointResolver;
  private final ObjectMapper objectMapper;

  @Inject
  public OAuth2RestClient(SCMContextProvider contextProvider, AdvancedHttpClient httpClient, OAuth2Context context, EndpointResolver endpointResolver, ObjectMapper objectMapper) {
    this.contextProvider = contextProvider;
    this.httpClient = httpClient;
    this.context = context;
    this.endpointResolver = endpointResolver;
    this.objectMapper = objectMapper;
  }

  public TokenResponse exchangeCodeForToken(String code, String redirectUri, String codeVerifier) {
    OAuth2Configuration configuration = context.get();
    Endpoints endpoints = endpointResolver.resolve();

    AdvancedHttpResponse response = execute(() -> {
      FormContentBuilder form = httpClient.post(endpoints.getTokenUrl())
        .spanKind("OAuth2")
        .acceptStatusCodes(400, 401, 403)
        .disableCertificateValidation(isDevelopmentStageActive())
        .formContent()
        .field("grant_type", "authorization_code")
        .field("code", code)
        .field("redirect_uri", redirectUri)
        .field("client_id", configuration.getClientId())
        .field("client_secret", configuration.getClientSecret());

      if (!Strings.isNullOrEmpty(codeVerifier)) {
        form = form.field("code_verifier", codeVerifier);
      }

      return form.build().request();
    });

    int statusCode = response.getStatus();
    if (statusCode != HttpServletResponse.SC_OK) {
      throw new AuthenticationException("failed to exchange authorization code, token endpoint returned status " + statusCode);
    }

    JsonNode tokenResponse = readJson(response);
    JsonNode accessToken = tokenResponse.get("access_token");
    if (accessToken == null) {
      throw new AuthenticationException("token endpoint response does not contain an access_token");
    }

    return new TokenResponse(accessToken.asText(), optionalText(tokenResponse, "id_token"));
  }

  public JsonNode fetchUserInfo(String accessToken) {
    Endpoints endpoints = endpointResolver.resolve();

    AdvancedHttpResponse response = execute(() -> httpClient.get(endpoints.getUserinfoUrl())
      .spanKind("OAuth2")
      .acceptStatusCodes(400, 401, 403)
      .disableCertificateValidation(isDevelopmentStageActive())
      .header("Authorization", "Bearer " + accessToken)
      .request()
    );

    int statusCode = response.getStatus();
    if (statusCode != HttpServletResponse.SC_OK) {
      throw new AuthenticationException("failed to fetch userinfo, server returned status " + statusCode);
    }

    return readJson(response);
  }

  private JsonNode readJson(AdvancedHttpResponse response) {
    try {
      return objectMapper.readTree(response.contentAsString());
    } catch (IOException ex) {
      throw new AuthenticationException("failed to parse json response", ex);
    }
  }

  private String optionalText(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    return value.asText();
  }

  private boolean isDevelopmentStageActive() {
    return contextProvider.getStage() == Stage.DEVELOPMENT;
  }

  private AdvancedHttpResponse execute(RequestExecutor executor) {
    try {
      return executor.execute();
    } catch (IOException ex) {
      throw new AuthenticationException("failed to execute oauth2 request", ex);
    }
  }

  @FunctionalInterface
  private interface RequestExecutor {
    AdvancedHttpResponse execute() throws IOException;
  }
}
