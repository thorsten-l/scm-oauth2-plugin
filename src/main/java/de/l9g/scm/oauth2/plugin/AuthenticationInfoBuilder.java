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
import com.google.common.collect.ImmutableSet;
import org.apache.shiro.authc.AuthenticationInfo;
import sonia.scm.security.SyncingRealmHelper;
import sonia.scm.user.User;

import jakarta.inject.Inject;
import java.util.Set;

public class AuthenticationInfoBuilder {

  private final OAuth2RestClient restClient;
  private final UserInfoMapper userInfoMapper;
  private final SyncingRealmHelper syncingRealmHelper;
  private final GroupStore groupStore;
  private final IdTokenStore idTokenStore;
  private final AdminGroupSynchronizer adminGroupSynchronizer;
  private final GroupSynchronizer groupSynchronizer;
  private final UserMigration userMigration;
  private final AccessTokenRoleReader accessTokenRoleReader;

  @Inject
  public AuthenticationInfoBuilder(OAuth2RestClient restClient, UserInfoMapper userInfoMapper, SyncingRealmHelper syncingRealmHelper, GroupStore groupStore, IdTokenStore idTokenStore, AdminGroupSynchronizer adminGroupSynchronizer, GroupSynchronizer groupSynchronizer, UserMigration userMigration, AccessTokenRoleReader accessTokenRoleReader) {
    this.restClient = restClient;
    this.userInfoMapper = userInfoMapper;
    this.syncingRealmHelper = syncingRealmHelper;
    this.groupStore = groupStore;
    this.idTokenStore = idTokenStore;
    this.adminGroupSynchronizer = adminGroupSynchronizer;
    this.groupSynchronizer = groupSynchronizer;
    this.userMigration = userMigration;
    this.accessTokenRoleReader = accessTokenRoleReader;
  }

  public AuthenticationInfo create(String code, String redirectUri, String codeVerifier) {
    TokenResponse tokens = restClient.exchangeCodeForToken(code, redirectUri, codeVerifier);
    JsonNode userInfo = restClient.fetchUserInfo(tokens.getAccessToken());

    User user = userMigration.prepare(userInfoMapper.createUser(userInfo));
    syncingRealmHelper.store(user);

    Set<String> previousGroups = groupStore.get(user.getName());
    // sanitized once here, so that group entity, membership and authorization
    // all use the same names
    Set<String> groups = GroupNameSanitizer.sanitize(
      ImmutableSet.<String>builder()
        .addAll(userInfoMapper.createGroups(userInfo))
        .addAll(accessTokenRoleReader.read(tokens.getAccessToken()))
        .build()
    );
    groupStore.put(user.getName(), groups);
    groupSynchronizer.sync(user.getName(), previousGroups, groups);

    idTokenStore.put(user.getName(), tokens.getIdToken());
    adminGroupSynchronizer.sync(user.getName(), groups);

    return syncingRealmHelper.createAuthenticationInfo(Constants.NAME, user);
  }
}
