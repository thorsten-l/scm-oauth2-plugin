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

import org.apache.shiro.authc.AuthenticationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.user.User;
import sonia.scm.user.UserManager;
import sonia.scm.web.security.AdministrationContext;
import sonia.scm.web.security.PrivilegedAction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Tests the takeover of existing accounts: an external account (for example from a
 * previous ldap authentication) is migrated silently, an account with a local
 * password only with the explicit option, and attributes the claims do not deliver
 * (mail, display name, properties, active flag) keep their stored value.
 */
@ExtendWith(MockitoExtension.class)
class UserMigrationTest {

  private static final String NAME = "eid9573584";

  @Mock
  private OAuth2Context context;

  @Mock
  private UserManager userManager;

  @Mock
  private AdministrationContext administrationContext;

  private final OAuth2Configuration configuration = new OAuth2Configuration();

  private UserMigration migration;

  @BeforeEach
  void setUpMigration() {
    migration = new UserMigration(context, userManager, administrationContext);
    lenient().when(context.get()).thenReturn(configuration);
    lenient().doAnswer(invocation -> {
      invocation.getArgument(0, PrivilegedAction.class).run();
      return null;
    }).when(administrationContext).runAsAdmin(any(PrivilegedAction.class));
  }

  @Test
  void shouldCreateNewUserIfNoneExists() {
    when(userManager.get(NAME)).thenReturn(null);

    User result = migration.prepare(fromClaim("Christophe Merle", "merle@hitchhiker.com"));

    assertThat(result.getName()).isEqualTo(NAME);
    assertThat(result.getDisplayName()).isEqualTo("Christophe Merle");
    assertThat(result.isExternal()).isTrue();
  }

  @Test
  void shouldFallBackToNameAsDisplayNameForNewUsers() {
    when(userManager.get(NAME)).thenReturn(null);

    User result = migration.prepare(fromClaim(null, null));

    assertThat(result.getDisplayName()).isEqualTo(NAME);
  }

  @Test
  void shouldMigrateExistingExternalUser() {
    User ldapUser = externalUser("Christophe Merle", "merle@hitchhiker.com");
    when(userManager.get(NAME)).thenReturn(ldapUser);

    User result = migration.prepare(fromClaim("Christophe M. Merle", "new@hitchhiker.com"));

    assertThat(result.getName()).isEqualTo(NAME);
    assertThat(result.getDisplayName()).isEqualTo("Christophe M. Merle");
    assertThat(result.getMail()).isEqualTo("new@hitchhiker.com");
    assertThat(result.isExternal()).isTrue();
  }

  @Test
  void shouldKeepStoredMailIfTheClaimHasNone() {
    User ldapUser = externalUser("Christophe Merle", "merle@hitchhiker.com");
    when(userManager.get(NAME)).thenReturn(ldapUser);

    User result = migration.prepare(fromClaim("Christophe Merle", null));

    assertThat(result.getMail()).isEqualTo("merle@hitchhiker.com");
  }

  @Test
  void shouldKeepStoredDisplayNameIfTheClaimHasNone() {
    User ldapUser = externalUser("Christophe Merle", "merle@hitchhiker.com");
    when(userManager.get(NAME)).thenReturn(ldapUser);

    User result = migration.prepare(fromClaim(null, null));

    assertThat(result.getDisplayName()).isEqualTo("Christophe Merle");
  }

  @Test
  void shouldKeepStoredPropertiesAndActiveFlag() {
    User ldapUser = externalUser("Christophe Merle", "merle@hitchhiker.com");
    ldapUser.setProperty("some.plugin.setting", "value");
    ldapUser.setActive(false);
    when(userManager.get(NAME)).thenReturn(ldapUser);

    User result = migration.prepare(fromClaim("Christophe Merle", null));

    assertThat(result.getProperty("some.plugin.setting")).isEqualTo("value");
    // a deactivated account must not be reactivated by a login
    assertThat(result.isActive()).isFalse();
  }

  @Test
  void shouldNotTakeOverLocalAccountByDefault() {
    when(userManager.get(NAME)).thenReturn(localUser());

    assertThatThrownBy(() -> migration.prepare(fromClaim("Attacker", null)))
      .isInstanceOf(AuthenticationException.class)
      .hasMessageContaining(NAME);
  }

  @Test
  void shouldTakeOverLocalAccountIfMigrationIsEnabled() {
    configuration.setMigrateLocalUsers(true);
    when(userManager.get(NAME)).thenReturn(localUser());

    User result = migration.prepare(fromClaim("Christophe Merle", null));

    assertThat(result.isExternal()).isTrue();
    // the local password must not survive the migration
    assertThat(result.getPassword()).isNull();
  }

  @Test
  void shouldMigrateExternalUserWithoutTheFlag() {
    User ldapUser = externalUser("Christophe Merle", null);
    when(userManager.get(NAME)).thenReturn(ldapUser);

    assertThat(migration.prepare(fromClaim(null, null)).isExternal()).isTrue();
  }

  private User fromClaim(String displayName, String mail) {
    User user = new User(NAME);
    user.setDisplayName(displayName);
    user.setMail(mail);
    user.setExternal(true);
    return user;
  }

  private User externalUser(String displayName, String mail) {
    User user = new User(NAME, displayName, mail);
    user.setExternal(true);
    return user;
  }

  private User localUser() {
    User user = new User(NAME, "Local Admin", "admin@hitchhiker.com");
    user.setExternal(false);
    user.setPassword("$shiro1$hashed");
    return user;
  }
}
