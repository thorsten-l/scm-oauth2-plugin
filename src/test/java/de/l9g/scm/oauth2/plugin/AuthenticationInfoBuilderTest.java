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

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationInfoBuilderTest {

  private static final String CODE = "authorization-code";
  private static final String REDIRECT_URI = "https://scm.hitchhiker.com/scm/api/v2/oauth2/auth/callback";
  private static final String ACCESS_TOKEN = "access-token";
  private static final String VERIFIER = "code-verifier";

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
  private AuthenticationInfo authenticationInfo;

  @Test
  void shouldCreateAuthenticationInfo() throws Exception {
    JsonNode userInfo = new ObjectMapper().readTree("{\"preferred_username\":\"trillian\"}");
    User user = new User("trillian");
    Set<String> groups = Set.of("heartOfGold");

    Set<String> previousGroups = Set.of("restaurantAtTheEndOfTheUniverse");
    when(restClient.exchangeCodeForToken(CODE, REDIRECT_URI, VERIFIER)).thenReturn(new TokenResponse(ACCESS_TOKEN, "id-token"));
    when(restClient.fetchUserInfo(ACCESS_TOKEN)).thenReturn(userInfo);
    when(userInfoMapper.createUser(userInfo)).thenReturn(user);
    when(userMigration.prepare(user)).thenReturn(user);
    when(userInfoMapper.createGroups(userInfo)).thenReturn(groups);
    when(groupStore.get("trillian")).thenReturn(previousGroups);
    when(syncingRealmHelper.createAuthenticationInfo(any(), any(User.class))).thenReturn(authenticationInfo);

    AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder(restClient, userInfoMapper, syncingRealmHelper, groupStore, idTokenStore, adminGroupSynchronizer, groupSynchronizer, userMigration);
    AuthenticationInfo result = builder.create(CODE, REDIRECT_URI, VERIFIER);

    assertThat(result).isSameAs(authenticationInfo);
    verify(syncingRealmHelper).store(user);
    verify(groupStore).put("trillian", groups);
    verify(groupSynchronizer).sync("trillian", previousGroups, groups);
    verify(idTokenStore).put("trillian", "id-token");
    verify(adminGroupSynchronizer).sync("trillian", groups);
    verify(syncingRealmHelper).createAuthenticationInfo(Constants.NAME, user);
  }
}
