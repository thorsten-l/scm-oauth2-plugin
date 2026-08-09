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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class AccessTokenRoleReaderTest {

  /**
   * Shortened, but structurally identical to a keycloak access token.
   */
  private static final String PAYLOAD = "{"
    + "\"sub\":\"eid9573584\","
    + "\"realm_access\":{\"roles\":[\"SCM RZ-intern\",\"Maven User\",\"offline_access\"]},"
    + "\"resource_access\":{\"scm-server\":{\"roles\":[\"scmadmin\",\"csit\"]}},"
    + "\"groups\":[\"scmadmin\"]"
    + "}";

  @Mock
  private OAuth2Context context;

  private final OAuth2Configuration configuration = new OAuth2Configuration();

  private AccessTokenRoleReader reader;

  @BeforeEach
  void setUpReader() {
    reader = new AccessTokenRoleReader(context, new ObjectMapper());
    lenient().when(context.get()).thenReturn(configuration);
    configuration.setImportRealmRoles(true);
  }

  @Test
  void shouldReadRealmRoles() {
    Set<String> roles = reader.read(token(PAYLOAD));

    assertThat(roles).containsExactlyInAnyOrder("SCM RZ-intern", "Maven User", "offline_access");
  }

  @Test
  void shouldReadClientRolesFromNestedPath() {
    configuration.setRealmRolesPath("resource_access.scm-server.roles");

    assertThat(reader.read(token(PAYLOAD))).containsExactlyInAnyOrder("scmadmin", "csit");
  }

  @Test
  void shouldReadSingleValueClaim() {
    configuration.setRealmRolesPath("sub");

    assertThat(reader.read(token(PAYLOAD))).containsExactly("eid9573584");
  }

  @Test
  void shouldReturnNothingIfDisabled() {
    configuration.setImportRealmRoles(false);

    assertThat(reader.read(token(PAYLOAD))).isEmpty();
  }

  @Test
  void shouldReturnNothingForUnknownPath() {
    configuration.setRealmRolesPath("does.not.exist");

    assertThat(reader.read(token(PAYLOAD))).isEmpty();
  }

  @Test
  void shouldReturnNothingWithoutConfiguredPath() {
    configuration.setRealmRolesPath("");

    assertThat(reader.read(token(PAYLOAD))).isEmpty();
  }

  @Test
  void shouldReturnNothingForOpaqueAccessToken() {
    assertThat(reader.read("an-opaque-token-which-is-no-jwt")).isEmpty();
  }

  @Test
  void shouldReturnNothingForNullToken() {
    assertThat(reader.read(null)).isEmpty();
  }

  @Test
  void shouldNotFailOnBrokenPayload() {
    assertThat(reader.read("header." + encode("this is not json") + ".signature")).isEmpty();
  }

  @Test
  void shouldSupportArrayIndexInPath() {
    configuration.setRealmRolesPath("realm_access.roles.1");

    assertThat(reader.read(token(PAYLOAD))).containsExactly("Maven User");
  }

  private String token(String payload) {
    return "header." + encode(payload) + ".signature";
  }

  private String encode(String value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }
}
