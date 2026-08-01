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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.security.AssignedPermission;
import sonia.scm.security.SecuritySystem;
import sonia.scm.web.security.AdministrationContext;

import jakarta.inject.Inject;
import java.util.Collection;
import java.util.Set;

/**
 * Synchronizes the global administrator permission ("*") of a user with the
 * configured admin group on every login. If the group claim of the identity
 * provider contains the configured admin group, the permission is assigned,
 * otherwise a previously assigned permission is revoked again.
 *
 * If no admin group is configured, permissions are never touched.
 */
public class AdminGroupSynchronizer {

  private static final Logger LOG = LoggerFactory.getLogger(AdminGroupSynchronizer.class);

  private static final String ADMIN_PERMISSION = "*";

  private final OAuth2Context context;
  private final SecuritySystem securitySystem;
  private final AdministrationContext administrationContext;

  @Inject
  public AdminGroupSynchronizer(OAuth2Context context, SecuritySystem securitySystem, AdministrationContext administrationContext) {
    this.context = context;
    this.securitySystem = securitySystem;
    this.administrationContext = administrationContext;
  }

  public void sync(String principal, Set<String> groups) {
    String adminGroup = context.get().getAdminGroup();
    if (Strings.isNullOrEmpty(adminGroup)) {
      return;
    }

    boolean shouldBeAdmin = groups.contains(adminGroup);
    // permission modification requires elevated privileges, but during the
    // login the subject is not yet authenticated
    administrationContext.runAsAdmin(() -> syncAdminPermission(principal, shouldBeAdmin));
  }

  private void syncAdminPermission(String principal, boolean shouldBeAdmin) {
    Collection<AssignedPermission> assigned = securitySystem.getPermissions(
      permission -> !permission.isGroupPermission()
        && principal.equals(permission.getName())
        && ADMIN_PERMISSION.equals(permission.getPermission().getValue())
    );

    if (shouldBeAdmin && assigned.isEmpty()) {
      LOG.info("assigning global administrator permission to user {}", principal);
      securitySystem.addPermission(new AssignedPermission(principal, ADMIN_PERMISSION));
    } else if (!shouldBeAdmin) {
      for (AssignedPermission permission : assigned) {
        LOG.info("revoking global administrator permission from user {}", principal);
        securitySystem.deletePermission(permission);
      }
    }
  }
}
