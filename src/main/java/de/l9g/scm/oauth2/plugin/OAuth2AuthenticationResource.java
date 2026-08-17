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
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import org.apache.shiro.authc.AuthenticationException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.api.v2.resources.ErrorDto;
import sonia.scm.security.AllowAnonymousAccess;
import sonia.scm.util.HttpUtil;
import sonia.scm.web.VndMediaType;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;

/**
 * The two http endpoints of the authorization code flow.
 *
 * <ul>
 *   <li>{@code GET /api/v2/oauth2/auth} - starts the flow and redirects to the
 *       identity provider</li>
 *   <li>{@code GET /api/v2/oauth2/auth/callback} - the redirect target of the
 *       identity provider, exchanges the authorization code for a session</li>
 * </ul>
 *
 * <p>Both endpoints must be reachable without authentication, hence
 * {@code @AllowAnonymousAccess}. Everything an anonymous caller can influence is
 * therefore treated as untrusted: the {@code from} parameter is sanitized, the
 * state has to match the state cookie of the very same browser and error details
 * of the identity provider are logged instead of being sent back.
 *
 * @see StateStore
 * @see LoginHandler
 */
@OpenAPIDefinition(tags = {
  @Tag(name = "OAuth2 Plugin", description = "OAuth2/OIDC plugin provided endpoints")
})
@AllowAnonymousAccess
@Path(OAuth2AuthenticationResource.PATH)
public class OAuth2AuthenticationResource {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2AuthenticationResource.class);

  /** Path of this resource below {@code /api}, also used by the filter and the ui links. */
  public static final String PATH = "v2/oauth2/auth";

  /** Sub path of the callback, appended to {@link #PATH} to build the {@code redirect_uri}. */
  public static final String CALLBACK_PATH = "callback";

  private final OAuth2Context context;
  private final EndpointResolver endpointResolver;
  private final StateStore stateStore;
  private final LoginHandler loginHandler;

  @Inject
  public OAuth2AuthenticationResource(OAuth2Context context, EndpointResolver endpointResolver, StateStore stateStore, LoginHandler loginHandler) {
    this.context = context;
    this.endpointResolver = endpointResolver;
    this.stateStore = stateStore;
    this.loginHandler = loginHandler;
  }

  @GET
  @Path("")
  @Operation(summary = "OAuth2 login", description = "Redirects to the authorization endpoint of the configured identity provider.", tags = "OAuth2 Plugin")
  @ApiResponse(responseCode = "303", description = "redirect to the identity provider")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  /**
   * Starts the flow: remembers a new authorization request and redirects the
   * browser to the authorization endpoint of the identity provider.
   *
   * @param request current request, used to build the callback url and the cookie
   * @param from    path inside this instance the user wanted to reach, it is
   *                remembered with the state and used after a successful login
   * @return 303 to the identity provider including the state cookie, or 404 if
   *         oauth2 authentication is not enabled
   */
  public Response login(@Context HttpServletRequest request, @QueryParam("from") String from) {
    OAuth2Configuration configuration = context.get();
    if (!configuration.isEnabled()) {
      // pretend the endpoint does not exist as long as the plugin is unconfigured
      return Response.status(Response.Status.NOT_FOUND).build();
    }

    AuthorizationRequest authorizationRequest = stateStore.create(sanitizeRedirect(from));
    Endpoints endpoints = endpointResolver.resolve();
    URI authorizationUri = createAuthorizationUri(configuration, endpoints, createCallbackUri(request), authorizationRequest);

    LOG.debug("redirecting to authorization endpoint {}", endpoints.getAuthorizationUrl());
    return Response.seeOther(authorizationUri)
      .header(HttpHeaders.SET_COOKIE, StateCookie.create(request, authorizationRequest.getState()))
      .build();
  }

  @GET
  @Path(CALLBACK_PATH)
  @Operation(summary = "OAuth2 callback", description = "Callback endpoint for the authorization code flow.", tags = "OAuth2 Plugin")
  @ApiResponse(responseCode = "303", description = "authentication successful, redirect to the originally requested url")
  @ApiResponse(responseCode = "401", description = "authentication failed")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  /**
   * Redirect target of the identity provider. Validates the state, exchanges the
   * authorization code for a session and sends the browser to the url which was
   * remembered when the flow was started.
   *
   * @param request          current request, carries the state cookie
   * @param response         used by the login handler to set the access token cookie
   * @param code             authorization code, to be redeemed at the token endpoint
   * @param state            state of the authorization request, has to match the cookie
   * @param error            error code, set instead of the code if the provider refused
   * @param errorDescription human readable error of the provider, only logged
   * @return 303 to the originally requested url on success, otherwise 401
   */
  public Response callback(
    @Context HttpServletRequest request,
    @Context HttpServletResponse response,
    @QueryParam("code") String code,
    @QueryParam("state") String state,
    @QueryParam("error") String error,
    @QueryParam("error_description") String errorDescription
  ) {
    if (!Strings.isNullOrEmpty(error)) {
      LOG.warn("identity provider returned error '{}': {}", error, errorDescription);
      return unauthorized(request, "identity provider returned an error");
    }

    // the state must have been issued to this browser, otherwise an attacker
    // could log a victim in with an authorization code of his own account
    if (!isStateBoundToBrowser(request, state)) {
      LOG.warn("callback called with a state which does not belong to the state cookie of the browser");
      return unauthorized(request, "state does not match");
    }

    // consuming removes the state, so a replay of the same callback url fails here
    Optional<AuthorizationRequest> authorizationRequest = stateStore.consume(state);
    if (!authorizationRequest.isPresent()) {
      LOG.warn("callback called with unknown or expired state");
      return unauthorized(request, "unknown or expired state");
    }

    if (Strings.isNullOrEmpty(code)) {
      return unauthorized(request, "missing authorization code");
    }

    OAuth2Token token = OAuth2Token.valueOf(
      code,
      createCallbackUri(request),
      authorizationRequest.get().getCodeVerifier(),
      authorizationRequest.get().getNonce()
    );
    LOG.debug("got callback from identity provider, logging in");
    try {
      loginHandler.login(request, response, token);
    } catch (AuthenticationException ex) {
      // the message of the exception may contain internals, so it is only logged
      LOG.warn("authentication of the oauth2 callback failed", ex);
      return unauthorized(request, "authentication failed");
    }

    // getCompleteUrl prefixes the base url of this instance, so only an absolute
    // url of this server can be produced from the remembered path
    String url = HttpUtil.getCompleteUrl(request, authorizationRequest.get().getRedirectUrl());
    return Response.seeOther(URI.create(url))
      .header(HttpHeaders.SET_COOKIE, StateCookie.invalidate(request))
      .build();
  }

  /**
   * Compares the state of the query with the state cookie of the browser in
   * constant time, so the comparison itself does not leak the expected value.
   */
  private boolean isStateBoundToBrowser(HttpServletRequest request, String state) {
    if (Strings.isNullOrEmpty(state)) {
      return false;
    }
    return StateCookie.read(request)
      .filter(fromCookie -> MessageDigest.isEqual(
        fromCookie.getBytes(StandardCharsets.UTF_8),
        state.getBytes(StandardCharsets.UTF_8)
      ))
      .isPresent();
  }

  /**
   * The callback url has to be identical in the authorization request and in the
   * code exchange, and it has to be registered at the identity provider as a
   * valid redirect uri.
   */
  private String createCallbackUri(HttpServletRequest request) {
    return HttpUtil.getCompleteUrl(request, "api", PATH, CALLBACK_PATH);
  }

  /**
   * Builds the authorization request as query parameters (rfc 6749, section 4.1.1).
   * The url of the endpoint may already contain a query, therefore the separator
   * is determined dynamically.
   */
  private URI createAuthorizationUri(OAuth2Configuration configuration, Endpoints endpoints, String redirectUri, AuthorizationRequest authorizationRequest) {
    String authorizationUrl = endpoints.getAuthorizationUrl();
    String separator = authorizationUrl.contains("?") ? "&" : "?";

    StringBuilder uri = new StringBuilder(authorizationUrl)
      .append(separator).append("response_type=code")
      .append("&client_id=").append(HttpUtil.encode(configuration.getClientId()))
      .append("&redirect_uri=").append(HttpUtil.encode(redirectUri))
      .append("&scope=").append(HttpUtil.encode(configuration.getScopes()))
      .append("&state=").append(HttpUtil.encode(authorizationRequest.getState()))
      // the identity provider echoes the nonce into the id token, which binds the
      // token to this login (OIDC Core 3.1.2.1)
      .append("&nonce=").append(HttpUtil.encode(authorizationRequest.getNonce()));

    if (endpoints.supportsPkce()) {
      // only the challenge leaves the server, the verifier stays in the state
      // store until the code is exchanged
      uri.append("&code_challenge=")
        .append(HttpUtil.encode(Pkce.createChallenge(authorizationRequest.getCodeVerifier())))
        .append("&code_challenge_method=").append(Pkce.METHOD);
    }

    return URI.create(uri.toString());
  }

  /**
   * Only paths of this instance are accepted as redirect target. Protocol
   * relative urls like {@code //example.com} would point to another host, even
   * though they start with a slash.
   */
  private String sanitizeRedirect(String from) {
    if (Strings.isNullOrEmpty(from)
      || !from.startsWith("/")
      || from.startsWith("//")
      || from.startsWith("/\\")
      || from.indexOf('\r') >= 0
      || from.indexOf('\n') >= 0) {
      return "/";
    }
    return from;
  }

  /**
   * The message is intentionally static, values received from the identity
   * provider are only written to the log and never reflected to the client.
   */
  private Response unauthorized(HttpServletRequest request, String message) {
    return Response.status(Response.Status.UNAUTHORIZED)
      .header(HttpHeaders.SET_COOKIE, StateCookie.invalidate(request))
      .type(MediaType.TEXT_PLAIN)
      .entity(message)
      .build();
  }

}
