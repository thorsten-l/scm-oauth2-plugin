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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests the reading of roles out of the claims of a verified access token: realm
 * roles, client roles at a nested path, single values and array indexes. The
 * remaining cases make sure that nothing but an empty set happens if the feature is
 * disabled, the path is missing or unknown, or the verifier could not verify the
 * token - none of these may break a login, and none of them may produce roles.
 *
 * <p>The signature verification itself is covered by {@code TokenVerifierTest}, here
 * the verifier is a mock.
 */
@ExtendWith(MockitoExtension.class)
class AccessTokenRoleReaderTest {

  /**
   * Shortened, but structurally identical to a keycloak access token.
   */
  private static final String PAYLOAD = "{"
    + "\"sub\":\"subject-of-the-token\","
    + "\"realm_access\":{\"roles\":[\"SCM RZ-intern\",\"Maven User\",\"offline_access\"]},"
    + "\"resource_access\":{\"scm-server\":{\"roles\":[\"scmadmin\",\"csit\"]}},"
    + "\"groups\":[\"scmadmin\"]"
    + "}";

  private static final String ACCESS_TOKEN = "the-access-token";

  @Mock
  private OAuth2Context context;

  @Mock
  private TokenVerifier tokenVerifier;

  private final OAuth2Configuration configuration = new OAuth2Configuration();

  private AccessTokenRoleReader reader;

  @BeforeEach
  void setUpReader() {
    reader = new AccessTokenRoleReader(context, tokenVerifier);
    lenient().when(context.get()).thenReturn(configuration);
    configuration.setImportRealmRoles(true);
  }

  @Test
  void shouldReadRealmRoles() {
    verifiedToken();

    Set<String> roles = reader.read(ACCESS_TOKEN);

    assertThat(roles).containsExactlyInAnyOrder("SCM RZ-intern", "Maven User", "offline_access");
  }

  @Test
  void shouldReadClientRolesFromNestedPath() {
    configuration.setRealmRolesPath("resource_access.scm-server.roles");
    verifiedToken();

    assertThat(reader.read(ACCESS_TOKEN)).containsExactlyInAnyOrder("scmadmin", "csit");
  }

  @Test
  void shouldReadSingleValueClaim() {
    configuration.setRealmRolesPath("sub");
    verifiedToken();

    assertThat(reader.read(ACCESS_TOKEN)).containsExactly("subject-of-the-token");
  }

  @Test
  void shouldReturnNothingIfDisabled() {
    configuration.setImportRealmRoles(false);

    assertThat(reader.read(ACCESS_TOKEN)).isEmpty();
    // the token is not even looked at when the import is switched off
    verifyNoInteractions(tokenVerifier);
  }

  @Test
  void shouldReturnNothingForUnknownPath() {
    configuration.setRealmRolesPath("does.not.exist");
    verifiedToken();

    assertThat(reader.read(ACCESS_TOKEN)).isEmpty();
  }

  @Test
  void shouldReturnNothingWithoutConfiguredPath() {
    configuration.setRealmRolesPath("");

    assertThat(reader.read(ACCESS_TOKEN)).isEmpty();
    verifyNoInteractions(tokenVerifier);
  }

  @Test
  void shouldNotImportRolesFromAnUnverifiableToken() {
    // opaque, forged or unverifiable — the verifier answers with nothing and no role
    // may be derived from the token
    when(tokenVerifier.verifyAccessToken(ACCESS_TOKEN)).thenReturn(Optional.empty());

    assertThat(reader.read(ACCESS_TOKEN)).isEmpty();
  }

  @Test
  void shouldReturnNothingForNullToken() {
    when(tokenVerifier.verifyAccessToken(null)).thenReturn(Optional.empty());

    assertThat(reader.read(null)).isEmpty();
  }

  @Test
  void shouldSupportArrayIndexInPath() {
    configuration.setRealmRolesPath("realm_access.roles.1");
    verifiedToken();

    assertThat(reader.read(ACCESS_TOKEN)).containsExactly("Maven User");
  }

  /**
   * Lets the verifier answer with the claims of a token it accepted.
   */
  private void verifiedToken() {
    when(tokenVerifier.verifyAccessToken(ACCESS_TOKEN)).thenReturn(Optional.of(claims()));
  }

  private JsonNode claims() {
    try {
      return new ObjectMapper().readTree(PAYLOAD);
    } catch (IOException ex) {
      throw new IllegalStateException("could not read the test payload", ex);
    }
  }
}
