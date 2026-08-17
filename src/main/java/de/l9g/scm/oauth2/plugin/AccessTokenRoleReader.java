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
 * <p>Roles are group memberships and therefore the basis of authorization. They are
 * only read from a token whose signature {@link TokenVerifier} could verify - an
 * opaque token, a token with an invalid signature or a missing key set means no
 * roles, never roles from unverified data.
 */
public class AccessTokenRoleReader {

  private static final Logger LOG = LoggerFactory.getLogger(AccessTokenRoleReader.class);

  private final OAuth2Context context;
  private final TokenVerifier tokenVerifier;

  @Inject
  public AccessTokenRoleReader(OAuth2Context context, TokenVerifier tokenVerifier) {
    this.context = context;
    this.tokenVerifier = tokenVerifier;
  }

  /**
   * Reads the roles at the configured path.
   *
   * @param accessToken access token of the code exchange
   * @return the roles, still unsanitized; empty if the import is disabled, no path
   *         is configured, the token could not be verified or the path does not exist
   */
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

    Optional<JsonNode> payload = tokenVerifier.verifyAccessToken(accessToken);
    if (!payload.isPresent()) {
      // the verifier already logged why the token could not be used
      LOG.debug("no verified access token available, skipping the role import");
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

  /**
   * Walks the dot separated path through the payload. A part consisting only of
   * digits is treated as an array index, so {@code audiences.0} works as well.
   */
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

  /**
   * Accepts an array as well as a single value at the end of the path, empty
   * entries are dropped.
   */
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
