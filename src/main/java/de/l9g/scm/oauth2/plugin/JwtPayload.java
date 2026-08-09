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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Reads the payload of a json web token without verifying its signature.
 *
 * <p>This is only used for tokens which were received directly from the token
 * endpoint of the identity provider over an authenticated tls connection, or
 * for values which are used as a lookup key only. Tokens from an untrusted
 * source must not be evaluated with this class.
 */
final class JwtPayload {

  private JwtPayload() {
  }

  static Optional<JsonNode> read(String token, ObjectMapper objectMapper) {
    if (Strings.isNullOrEmpty(token)) {
      return Optional.empty();
    }

    String[] parts = token.split("\\.");
    if (parts.length < 2) {
      return Optional.empty();
    }

    try {
      byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
      return Optional.ofNullable(objectMapper.readTree(new String(payload, StandardCharsets.UTF_8)));
    } catch (IOException | IllegalArgumentException ex) {
      return Optional.empty();
    }
  }
}
