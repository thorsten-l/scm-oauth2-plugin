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
 *
 * <p>Which claim is used for what is configurable, see
 * {@link OAuth2Configuration}. Claims may be missing or may be arrays instead of
 * single values (a keycloak mapper with "multivalued" for instance), therefore
 * every read goes through {@code getStringClaim}.
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
   *
   * @param userInfo parsed userinfo response
   * @return user which is not persisted yet
   * @throws AuthenticationException if no usable user name can be determined
   */
  public User createUser(JsonNode userInfo) {
    String username = getUsername(userInfo);

    User user = new User(username);
    user.setDisplayName(getStringClaim(userInfo, context.get().getDisplayNameAttribute()));
    setEmail(userInfo, user);
    // external means: authenticated elsewhere, no local password
    user.setExternal(true);

    return user;
  }

  /**
   * Reads the group names of the configured claim.
   *
   * @param userInfo parsed userinfo response
   * @return the group names as they were delivered, still unsanitized; empty if
   *         the claim is missing
   */
  public Set<String> createGroups(JsonNode userInfo) {
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();

    JsonNode groups = userInfo.get(context.get().getGroupAttribute());
    if (groups != null) {
      // a single group may arrive as a plain string instead of an array
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

  /**
   * The user name is the identity inside SCM-Manager, every permission and every
   * repository ownership refers to it. The {@code sub} claim is used as fallback,
   * it is guaranteed to exist in OIDC - not pretty, but better than a failed login.
   */
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

  /**
   * An invalid mail address would make the core reject the user, which would break
   * the login completely. Therefore it is dropped with a log entry instead.
   *
   * <p>The address itself is not written to the log: it is personal data which is
   * not needed to fix the problem (the claim of the identity provider is the place
   * to look). Only the length is reported, which is enough to tell an empty value
   * apart from a malformed one.
   */
  private void setEmail(JsonNode userInfo, User user) {
    String mail = getStringClaim(userInfo, context.get().getMailAttribute());
    if (ValidationUtil.isMailAddressValid(mail)) {
      user.setMail(mail);
    } else if (!Strings.isNullOrEmpty(mail)) {
      LOG.info(
        "the mail claim of oauth2 user '{}' is not a valid mail address ({} characters); leaving email blank",
        user.getName(), mail.length()
      );
    }
  }

  /**
   * Reads a claim as string. Arrays are reduced to their first element, because
   * some providers deliver even single values as an array.
   *
   * @return value of the claim or {@code null} if it is missing, json null or an
   *         empty array
   */
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
