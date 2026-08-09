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
import org.apache.shiro.authc.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.user.User;
import sonia.scm.util.ValidationUtil;

import jakarta.inject.Inject;
import java.util.Set;

/**
 * Maps the claims of an OIDC userinfo response to an SCM-Manager user
 * and its group memberships.
 */
public class UserInfoMapper {

  private static final Logger LOG = LoggerFactory.getLogger(UserInfoMapper.class);

  private static final String SUBJECT_CLAIM = "sub";

  private final OAuth2Context context;

  @Inject
  public UserInfoMapper(OAuth2Context context) {
    this.context = context;
  }

  /**
   * Creates a user from the claims. Attributes which the identity provider does
   * not deliver are left empty on purpose, so that {@link UserMigration} can
   * keep the stored value of an already existing account.
   */
  public User createUser(JsonNode userInfo) {
    String username = getUsername(userInfo);

    User user = new User(username);
    user.setDisplayName(getStringClaim(userInfo, context.get().getDisplayNameAttribute()));
    setEmail(userInfo, user);
    user.setExternal(true);

    return user;
  }

  public Set<String> createGroups(JsonNode userInfo) {
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();

    JsonNode groups = userInfo.get(context.get().getGroupAttribute());
    if (groups != null) {
      if (groups.isArray()) {
        for (JsonNode group : groups) {
          builder.add(group.asText());
        }
      } else {
        builder.add(groups.asText());
      }
    }

    return builder.build();
  }

  private String getUsername(JsonNode userInfo) {
    String username = getStringClaim(userInfo, context.get().getUsernameAttribute());
    if (Strings.isNullOrEmpty(username)) {
      username = getStringClaim(userInfo, SUBJECT_CLAIM);
    }
    if (Strings.isNullOrEmpty(username)) {
      throw new AuthenticationException("userinfo response contains neither the configured username attribute nor a sub claim");
    }
    return username;
  }

  private void setEmail(JsonNode userInfo, User user) {
    String mail = getStringClaim(userInfo, context.get().getMailAttribute());
    if (ValidationUtil.isMailAddressValid(mail)) {
      user.setMail(mail);
    } else if (!Strings.isNullOrEmpty(mail)) {
      LOG.info("found invalid email address '{}' for oauth2 user '{}'; leaving email blank", mail, user.getName());
    }
  }

  private String getStringClaim(JsonNode userInfo, String claimName) {
    JsonNode claim = userInfo.get(claimName);
    if (claim == null || claim.isNull()) {
      return null;
    }
    if (claim.isArray()) {
      return claim.isEmpty() ? null : claim.get(0).asText();
    }
    return claim.asText();
  }
}
