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

package de.l9g.scm.oauth2.plugin.config;

import com.google.common.base.Strings;
import de.l9g.scm.oauth2.plugin.Constants;
import de.l9g.scm.oauth2.plugin.OAuth2Configuration;
import de.l9g.scm.oauth2.plugin.OAuth2Context;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import sonia.scm.api.v2.resources.ErrorDto;
import sonia.scm.config.ConfigurationPermissions;
import sonia.scm.web.VndMediaType;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * REST endpoint of the plugin configuration, used by the administration ui.
 *
 * <p>Both methods check the permissions {@code configuration:read:oauth2} and
 * {@code configuration:write:oauth2}, which are declared in
 * {@code META-INF/scm/permissions.xml}.
 *
 * <p>Beyond a plain read and write there are three rules to be aware of:
 *
 * <ul>
 *   <li>the client secret is never handed out, and an empty secret on update keeps
 *       the stored one</li>
 *   <li>a provider name is mandatory as soon as the plugin is enabled, because the
 *       login button is labelled with it</li>
 *   <li>only absolute http and https urls are accepted as endpoints</li>
 * </ul>
 */
@Path(ConfigurationResource.PATH)
public class ConfigurationResource {

  private static final String CONTENT_TYPE = VndMediaType.PREFIX + "oauth2Config" + VndMediaType.SUFFIX;

  /** Path of this resource below {@code /api}. */
  public static final String PATH = "v2/oauth2/configuration";

  private final OAuth2Context context;
  private final ConfigurationMapper mapper;

  @Inject
  public ConfigurationResource(OAuth2Context context, ConfigurationMapper mapper) {
    this.context = context;
    this.mapper = mapper;
  }

  @GET
  @Path("")
  @Produces(CONTENT_TYPE)
  @Operation(summary = "Get oauth2 configuration", description = "Returns the oauth2 configuration.", tags = "OAuth2 Plugin")
  @ApiResponse(
    responseCode = "200",
    description = "success",
    content = @Content(
      mediaType = CONTENT_TYPE,
      schema = @Schema(implementation = ConfigurationDto.class)
    )
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized /  the current user does not have the \"configuration:read:oauth2\" privilege")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  /**
   * @return the current configuration without the client secret, but with the hint
   *         whether one is stored
   * @throws org.apache.shiro.authz.AuthorizationException if the permission
   *         {@code configuration:read:oauth2} is missing
   */
  public ConfigurationDto get() {
    ConfigurationPermissions.read(Constants.NAME).check();
    OAuth2Configuration configuration = context.get();
    ConfigurationDto dto = mapper.toDto(configuration);
    // the client secret is write only, it is never handed out again
    dto.setClientSecret(null);
    dto.setClientSecretSet(!Strings.isNullOrEmpty(configuration.getClientSecret()));
    return dto;
  }

  @PUT
  @Path("")
  @Consumes(CONTENT_TYPE)
  @Operation(summary = "Update oauth2 configuration", description = "Modifies the oauth2 configuration.", tags = "OAuth2 Plugin")
  @ApiResponse(responseCode = "204", description = "update success")
  @ApiResponse(responseCode = "400", description = "invalid configuration, e.g. missing provider name")
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized /  the current user does not have the \"configuration:write:oauth2\" privilege")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  /**
   * Replaces the configuration completely.
   *
   * @param dto new configuration; an empty client secret means "keep the stored one"
   * @return 204 on success, 400 with a plain text reason if the configuration is invalid
   * @throws org.apache.shiro.authz.AuthorizationException if the permission
   *         {@code configuration:write:oauth2} is missing
   */
  public Response update(ConfigurationDto dto) {
    ConfigurationPermissions.write(Constants.NAME).check();

    if (dto.isEnabled() && Strings.isNullOrEmpty(dto.getProviderName())) {
      return badRequest("providerName is required if oauth2 authentication is enabled");
    }

    Optional<String> invalidUrl = findInvalidUrl(dto);
    if (invalidUrl.isPresent()) {
      return badRequest("only absolute http and https urls are allowed: " + invalidUrl.get());
    }

    OAuth2Configuration previous = context.get();
    OAuth2Configuration configuration = mapper.fromDto(dto);
    if (Strings.isNullOrEmpty(configuration.getClientSecret())) {
      // an empty secret means "keep the stored one", because it is never
      // handed out by the get endpoint
      configuration.setClientSecret(previous.getClientSecret());
    }

    context.set(configuration);
    return Response.noContent().build();
  }

  /**
   * The endpoints are requested by the server itself, so only absolute http
   * urls are accepted to limit what a holder of the configuration write
   * permission can make the server talk to.
   */
  private Optional<String> findInvalidUrl(ConfigurationDto dto) {
    return Stream.of(
        dto.getDiscoveryUrl(),
        dto.getAuthorizationUrl(),
        dto.getTokenUrl(),
        dto.getUserinfoUrl(),
        dto.getEndSessionUrl(),
        dto.getJwksUrl()
      )
      .filter(url -> !Strings.isNullOrEmpty(url))
      .filter(url -> !isHttpUrl(url))
      .findFirst();
  }

  /**
   * Rejects everything which is not an absolute http url with a host, so no
   * {@code file:}, {@code jar:} or relative url can be smuggled in.
   */
  private boolean isHttpUrl(String value) {
    try {
      URI uri = new URI(value);
      String scheme = uri.getScheme();
      return uri.isAbsolute()
        && uri.getHost() != null
        && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
    } catch (URISyntaxException ex) {
      return false;
    }
  }

  private Response badRequest(String message) {
    return Response.status(Response.Status.BAD_REQUEST)
      .type(MediaType.TEXT_PLAIN)
      .entity(message)
      .build();
  }
}
