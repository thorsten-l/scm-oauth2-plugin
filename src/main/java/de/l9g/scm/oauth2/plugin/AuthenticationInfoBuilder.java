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

/**
 * Everything which happens during a login, in one place. Called by the
 * {@link OAuth2Realm} with the data of the callback and responsible for the
 * complete provisioning of user, groups and permissions.
 *
 * <p>The order of the steps matters:
 *
 * <ol>
 *   <li>tokens are fetched and the id token is verified, so a failing or
 *       untrustworthy identity provider aborts the login before anything is
 *       written</li>
 *   <li>the claims are fetched</li>
 *   <li>the user is stored, because groups and permissions reference it</li>
 *   <li>the previous groups are read before the new ones are written, they are
 *       needed to revoke memberships which are gone</li>
 *   <li>group and permission synchronization happen last, they may fail without
 *       failing the login</li>
 * </ol>
 *
 * <p>This class is not an extension, it is instantiated by guice as a dependency
 * of the realm.
 */
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
  private final TokenVerifier tokenVerifier;

  @Inject
  public AuthenticationInfoBuilder(OAuth2RestClient restClient, UserInfoMapper userInfoMapper, SyncingRealmHelper syncingRealmHelper, GroupStore groupStore, IdTokenStore idTokenStore, AdminGroupSynchronizer adminGroupSynchronizer, GroupSynchronizer groupSynchronizer, UserMigration userMigration, AccessTokenRoleReader accessTokenRoleReader, TokenVerifier tokenVerifier) {
    this.restClient = restClient;
    this.userInfoMapper = userInfoMapper;
    this.syncingRealmHelper = syncingRealmHelper;
    this.groupStore = groupStore;
    this.idTokenStore = idTokenStore;
    this.adminGroupSynchronizer = adminGroupSynchronizer;
    this.groupSynchronizer = groupSynchronizer;
    this.userMigration = userMigration;
    this.accessTokenRoleReader = accessTokenRoleReader;
    this.tokenVerifier = tokenVerifier;
  }

  /**
   * Redeems the authorization code, provisions the user and returns the shiro
   * authentication info for the session.
   *
   * @param code         authorization code of the callback
   * @param redirectUri  callback url which was used in the authorization request,
   *                     the identity provider verifies that both are identical
   * @param codeVerifier pkce verifier of the authorization request, may be
   *                     {@code null} if pkce is not used
   * @param nonce        nonce of the authorization request, the id token has to carry
   *                     the same value
   * @return authentication info with the user as primary principal
   * @throws org.apache.shiro.authc.AuthenticationException if the identity
   *         provider refuses the code, the id token does not stand up to
   *         verification, the claims are unusable or a local account with the same
   *         name must not be taken over
   */
  public AuthenticationInfo create(String code, String redirectUri, String codeVerifier, String nonce) {
    TokenResponse tokens = restClient.exchangeCodeForToken(code, redirectUri, codeVerifier);

    // verified before anything else is done with the response: an id token which is
    // present but invalid means the response cannot be trusted at all
    boolean idTokenVerified = tokenVerifier.verifyIdToken(tokens.getIdToken(), nonce).isPresent();

    JsonNode userInfo = restClient.fetchUserInfo(tokens.getAccessToken());

    User user = userMigration.prepare(userInfoMapper.createUser(userInfo));
    // store() creates the user on the first login and updates it afterwards
    syncingRealmHelper.store(user);

    // read before the store is overwritten, the difference tells which
    // memberships have to be revoked
    Set<String> previousGroups = groupStore.get(user.getName());
    // sanitized once here, so that group entity, membership and authorization
    // all use the same names
    Set<String> groups = GroupNameSanitizer.sanitize(
      ImmutableSet.<String>builder()
        .addAll(userInfoMapper.createGroups(userInfo))
        .addAll(accessTokenRoleReader.read(tokens.getAccessToken()))
        .build()
    );
    // the store is what the group resolver reads, so authorization is already
    // based on the current claim even if the group entities cannot be updated
    groupStore.put(user.getName(), groups);
    groupSynchronizer.sync(user.getName(), previousGroups, groups);

    // needed as id_token_hint when the user logs out again; an unverified token is
    // not kept, so nothing which was not verified is ever used
    if (idTokenVerified) {
      idTokenStore.put(user.getName(), tokens.getIdToken());
    }
    adminGroupSynchronizer.sync(user.getName(), groups);

    return syncingRealmHelper.createAuthenticationInfo(Constants.NAME, user);
  }
}
