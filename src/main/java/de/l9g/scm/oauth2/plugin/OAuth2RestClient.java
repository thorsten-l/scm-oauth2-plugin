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
 *
 * <p>{@code AdvancedHttpClient} of the core is used on purpose instead of a own
 * http client: it honours the proxy settings of SCM-Manager and takes part in its
 * tracing ({@code spanKind}).
 *
 * <p>Error handling follows one rule: every failure becomes an
 * {@code AuthenticationException}, because every caller is part of a login. Status
 * codes 400, 401 and 403 are accepted explicitly, otherwise the client would throw
 * before the status can be logged with a useful message.
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

  /**
   * Redeems the authorization code at the token endpoint (rfc 6749, section 4.1.3).
   * The client authenticates itself with client id and secret in the form body.
   *
   * @param code         authorization code of the callback
   * @param redirectUri  callback url of the authorization request, has to be identical
   * @param codeVerifier pkce verifier, omitted if {@code null} or empty
   * @return access token and, if the provider issues one, the id token
   * @throws AuthenticationException if the request fails, the status is not 200 or
   *         the response contains no access token
   */
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

  /**
   * Reads the claims of the authenticated user from the userinfo endpoint.
   *
   * <p>Note for troubleshooting: which claims appear here is decided by the
   * identity provider. In keycloak a protocol mapper has to have "Add to userinfo"
   * enabled, otherwise the claim exists in the token but not in this response.
   *
   * @param accessToken access token of the code exchange
   * @return the parsed userinfo response
   * @throws AuthenticationException if the request fails or the status is not 200
   */
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

  /**
   * Certificate validation is only disabled while SCM-Manager runs in the
   * development stage ({@code ./gradlew run}), so a self signed test provider can
   * be used. In production the validation is always active.
   */
  private boolean isDevelopmentStageActive() {
    return contextProvider.getStage() == Stage.DEVELOPMENT;
  }

  /**
   * Wraps the checked {@code IOException} of the http client, so the callers stay
   * readable and every failure is an authentication failure.
   */
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
