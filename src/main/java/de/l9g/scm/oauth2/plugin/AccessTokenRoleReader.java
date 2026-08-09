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
import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import java.util.Optional;
import java.util.Set;

/**
 * Reads roles from the access token, e.g. the realm roles of keycloak at
 * {@code realm_access.roles}. Some identity providers put the roles only into
 * the access token and not into the userinfo response.
 *
 * <p>The path is a dot separated list of field names, array indexes are
 * supported as well, so {@code resource_access.scm-server.roles} works too.
 *
 * <p>The signature of the token is not verified, because it was received
 * directly from the token endpoint of the configured identity provider over
 * tls, exactly like the userinfo response.
 */
public class AccessTokenRoleReader {

  private static final Logger LOG = LoggerFactory.getLogger(AccessTokenRoleReader.class);

  private final OAuth2Context context;
  private final ObjectMapper objectMapper;

  @Inject
  public AccessTokenRoleReader(OAuth2Context context, ObjectMapper objectMapper) {
    this.context = context;
    this.objectMapper = objectMapper;
  }

  public Set<String> read(String accessToken) {
    OAuth2Configuration configuration = context.get();
    if (!configuration.isImportRealmRoles()) {
      return Set.of();
    }

    String path = configuration.getRealmRolesPath();
    if (Strings.isNullOrEmpty(path)) {
      LOG.warn("import of realm roles is enabled, but no path is configured");
      return Set.of();
    }

    Optional<JsonNode> payload = JwtPayload.read(accessToken, objectMapper);
    if (!payload.isPresent()) {
      LOG.warn("could not read the payload of the access token, it may not be a json web token");
      return Set.of();
    }

    Optional<JsonNode> roles = resolve(payload.get(), path);
    if (!roles.isPresent()) {
      LOG.debug("access token does not contain any roles at '{}'", path);
      return Set.of();
    }

    Set<String> values = toValues(roles.get());
    LOG.debug("read {} roles from the access token at '{}'", values.size(), path);
    return values;
  }

  private Optional<JsonNode> resolve(JsonNode payload, String path) {
    JsonNode node = payload;
    for (String part : path.split("\\.")) {
      if (node == null || node.isNull()) {
        return Optional.empty();
      }
      node = node.isArray() && isIndex(part) ? node.get(Integer.parseInt(part)) : node.get(part);
    }
    return Optional.ofNullable(node).filter(found -> !found.isNull());
  }

  private boolean isIndex(String part) {
    return part.chars().allMatch(Character::isDigit) && !part.isEmpty();
  }

  private Set<String> toValues(JsonNode node) {
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();
    if (node.isArray()) {
      node.forEach(item -> {
        if (!item.isNull() && !Strings.isNullOrEmpty(item.asText())) {
          builder.add(item.asText());
        }
      });
    } else if (!Strings.isNullOrEmpty(node.asText())) {
      builder.add(node.asText());
    }
    return builder.build();
  }
}
