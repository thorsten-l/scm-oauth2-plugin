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
import org.apache.shiro.authc.AuthenticationInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.security.SyncingRealmHelper;
import sonia.scm.user.User;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Verifies the orchestration of a login: every collaborator is a mock, so the test
 * documents the order and the arguments of the steps. It also proves that groups of
 * the claim and roles of the access token end up merged and sanitized in the group
 * store, in the synchronizers and in the authorization.
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationInfoBuilderTest {

  private static final String CODE = "authorization-code";
  private static final String REDIRECT_URI = "https://scm.hitchhiker.com/scm/api/v2/oauth2/auth/callback";
  private static final String ACCESS_TOKEN = "access-token";
  private static final String VERIFIER = "code-verifier";
  private static final String NONCE = "the-nonce";

  @Mock
  private OAuth2RestClient restClient;

  @Mock
  private UserInfoMapper userInfoMapper;

  @Mock
  private SyncingRealmHelper syncingRealmHelper;

  @Mock
  private GroupStore groupStore;

  @Mock
  private IdTokenStore idTokenStore;

  @Mock
  private AdminGroupSynchronizer adminGroupSynchronizer;

  @Mock
  private GroupSynchronizer groupSynchronizer;

  @Mock
  private UserMigration userMigration;

  @Mock
  private AccessTokenRoleReader accessTokenRoleReader;

  @Mock
  private TokenVerifier tokenVerifier;

  @Mock
  private AuthenticationInfo authenticationInfo;

  @Test
  void shouldCreateAuthenticationInfo() throws Exception {
    JsonNode userInfo = new ObjectMapper().readTree("{\"preferred_username\":\"trillian\"}");
    User user = new User("trillian");
    Set<String> groups = Set.of("heartOfGold");
    // the slash of the realm role is replaced on the way
    Set<String> merged = Set.of("heartOfGold", "_realm-role");

    Set<String> previousGroups = Set.of("restaurantAtTheEndOfTheUniverse");
    when(restClient.exchangeCodeForToken(CODE, REDIRECT_URI, VERIFIER)).thenReturn(new TokenResponse(ACCESS_TOKEN, "id-token"));
    when(restClient.fetchUserInfo(ACCESS_TOKEN)).thenReturn(userInfo);
    when(userInfoMapper.createUser(userInfo)).thenReturn(user);
    when(userMigration.prepare(user)).thenReturn(user);
    when(userInfoMapper.createGroups(userInfo)).thenReturn(groups);
    when(accessTokenRoleReader.read(ACCESS_TOKEN)).thenReturn(Set.of("/realm-role"));
    when(groupStore.get("trillian")).thenReturn(previousGroups);
    when(syncingRealmHelper.createAuthenticationInfo(any(), any(User.class))).thenReturn(authenticationInfo);
    // the id token was verified, so it may be kept for the logout
    when(tokenVerifier.verifyIdToken("id-token", NONCE)).thenReturn(Optional.of(userInfo));

    AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder(restClient, userInfoMapper, syncingRealmHelper, groupStore, idTokenStore, adminGroupSynchronizer, groupSynchronizer, userMigration, accessTokenRoleReader, tokenVerifier);
    AuthenticationInfo result = builder.create(CODE, REDIRECT_URI, VERIFIER, NONCE);

    assertThat(result).isSameAs(authenticationInfo);
    verify(syncingRealmHelper).store(user);
    verify(groupStore).put("trillian", merged);
    verify(groupSynchronizer).sync("trillian", previousGroups, merged);
    verify(idTokenStore).put("trillian", "id-token");
    verify(adminGroupSynchronizer).sync("trillian", merged);
    verify(syncingRealmHelper).createAuthenticationInfo(Constants.NAME, user);
  }

  @Test
  void shouldNotKeepAnIdTokenWhichCouldNotBeVerified() throws Exception {
    JsonNode userInfo = new ObjectMapper().readTree("{\"preferred_username\":\"trillian\"}");
    User user = new User("trillian");

    when(restClient.exchangeCodeForToken(CODE, REDIRECT_URI, VERIFIER)).thenReturn(new TokenResponse(ACCESS_TOKEN, "id-token"));
    when(restClient.fetchUserInfo(ACCESS_TOKEN)).thenReturn(userInfo);
    when(userInfoMapper.createUser(userInfo)).thenReturn(user);
    when(userMigration.prepare(user)).thenReturn(user);
    when(syncingRealmHelper.createAuthenticationInfo(any(), any(User.class))).thenReturn(authenticationInfo);
    // no key material: the verifier cannot verify the token
    when(tokenVerifier.verifyIdToken("id-token", NONCE)).thenReturn(Optional.empty());

    AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder(restClient, userInfoMapper, syncingRealmHelper, groupStore, idTokenStore, adminGroupSynchronizer, groupSynchronizer, userMigration, accessTokenRoleReader, tokenVerifier);
    builder.create(CODE, REDIRECT_URI, VERIFIER, NONCE);

    // an unverified token is not used for the logout hint either
    verifyNoInteractions(idTokenStore);
  }
}
