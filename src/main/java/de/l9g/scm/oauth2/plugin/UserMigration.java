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

import com.google.common.base.Strings;
import org.apache.shiro.authc.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.user.User;
import sonia.scm.user.UserManager;
import sonia.scm.web.security.AdministrationContext;

import jakarta.inject.Inject;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Takes over users which already exist in SCM-Manager, e.g. when an instance
 * is switched from ldap authentication to oauth2 and the identity provider
 * delivers the same user names.
 *
 * <p>Everything which is bound to the user name (permissions, repository
 * ownership, group memberships, api keys) is kept automatically, because the
 * account itself is reused. In addition all attributes which the identity
 * provider does not deliver are preserved, so that for example a stored mail
 * address does not get lost if the userinfo response contains no mail claim.
 *
 * <p>Accounts which can still be used for a local password login are not taken
 * over unless the administrator allows it explicitly, because otherwise a user
 * of the identity provider could seize a local account (for instance the
 * initial administrator) just by using its name.
 */
public class UserMigration {

  private static final Logger LOG = LoggerFactory.getLogger(UserMigration.class);

  private final OAuth2Context context;
  private final UserManager userManager;
  private final AdministrationContext administrationContext;

  @Inject
  public UserMigration(OAuth2Context context, UserManager userManager, AdministrationContext administrationContext) {
    this.context = context;
    this.userManager = userManager;
    this.administrationContext = administrationContext;
  }

  /**
   * Merges the user built from the claims with a possibly existing account.
   *
   * @param fromClaim user as delivered by the {@link UserInfoMapper}
   * @return the user to persist: either the unchanged new user or the existing
   *         account updated with the values of the claims
   * @throws AuthenticationException if an account with a local password exists and
   *         the takeover of local accounts is not enabled
   */
  public User prepare(User fromClaim) {
    User existing = findExisting(fromClaim.getName());

    if (existing == null) {
      // first login of this user, nothing to migrate
      return withDisplayNameFallback(fromClaim, fromClaim.getName());
    }

    if (isLocalAccount(existing) && !context.get().isMigrateLocalUsers()) {
      LOG.warn(
        "refusing to authenticate '{}', because a local account with this name exists; "
          + "enable the migration of local accounts in the oauth2 configuration if this is intended",
        existing.getName()
      );
      throw new AuthenticationException("a local account with the name " + existing.getName() + " already exists");
    }

    return merge(fromClaim, existing);
  }

  /**
   * The user is not authenticated yet while the login is processed, so the
   * lookup needs elevated privileges.
   */
  private User findExisting(String name) {
    AtomicReference<User> reference = new AtomicReference<>();
    administrationContext.runAsAdmin(() -> reference.set(userManager.get(name)));
    return reference.get();
  }

  /**
   * An account which is not marked as external and still has a password can be
   * used for a local login, so it must not be seized by the identity provider.
   * Users which were synchronized by another external authentication (ldap,
   * cas) have no password and are migrated silently.
   */
  private boolean isLocalAccount(User user) {
    return !user.isExternal() && !Strings.isNullOrEmpty(user.getPassword());
  }

  /**
   * The existing account is the base, so everything which is not part of the claims
   * survives. It is cloned, because the instance of the user manager must not be
   * modified in place.
   */
  private User merge(User fromClaim, User existing) {
    User user = existing.clone();

    // attributes which the identity provider does not deliver keep their
    // stored value, everything else is updated from the claims
    if (!Strings.isNullOrEmpty(fromClaim.getDisplayName())) {
      user.setDisplayName(fromClaim.getDisplayName());
    }
    if (!Strings.isNullOrEmpty(fromClaim.getMail())) {
      user.setMail(fromClaim.getMail());
    }

    // the account is authenticated by the identity provider from now on, a
    // leftover local password would be a second way in
    user.setExternal(true);
    user.setPassword(null);

    if (!existing.isExternal()) {
      LOG.info("migrating local account '{}' to oauth2 authentication", existing.getName());
    } else {
      LOG.debug("reusing existing external account '{}'", existing.getName());
    }

    return withDisplayNameFallback(user, existing.getName());
  }

  /**
   * SCM-Manager requires a display name, so the user name is used if neither the
   * claims nor the stored account provide one.
   */
  private User withDisplayNameFallback(User user, String name) {
    if (Strings.isNullOrEmpty(user.getDisplayName())) {
      user.setDisplayName(name);
    }
    return user;
  }
}
