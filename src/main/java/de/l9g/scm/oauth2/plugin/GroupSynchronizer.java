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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.group.Group;
import sonia.scm.group.GroupManager;
import sonia.scm.util.ValidationUtil;
import sonia.scm.web.security.AdministrationContext;

import jakarta.inject.Inject;
import java.util.Set;

/**
 * Synchronizes the groups of the group claim with the scm group database on
 * every login:
 *
 * <ul>
 *   <li>groups which do not exist yet are created with the user as member</li>
 *   <li>the user is added as member to existing groups from the claim</li>
 *   <li>the user is removed from groups which were synchronized on a previous
 *       login, but are no longer part of the claim</li>
 *   <li>groups are never deleted, even if they become empty</li>
 * </ul>
 *
 * Only groups which were previously synchronized for this user are touched on
 * removal, so manually maintained memberships in other groups are preserved.
 * External groups are skipped, their members are not managed by SCM-Manager.
 *
 * <p>This synchronization is a convenience feature: it makes the groups visible in
 * the administration ui so permissions can be granted to them. Authorization
 * itself does not depend on it, it is based on the {@link GroupStore} through the
 * {@link OAuth2GroupResolver}. That is why every failure in here is logged and
 * swallowed.
 */
public class GroupSynchronizer {

  private static final Logger LOG = LoggerFactory.getLogger(GroupSynchronizer.class);

  private static final String GROUP_TYPE = "xml";
  private static final String GROUP_DESCRIPTION = "Synchronized by scm-oauth2-plugin";

  private final GroupManager groupManager;
  private final AdministrationContext administrationContext;

  @Inject
  public GroupSynchronizer(GroupManager groupManager, AdministrationContext administrationContext) {
    this.groupManager = groupManager;
    this.administrationContext = administrationContext;
  }

  /**
   * Aligns the group database with the claim of the current login.
   *
   * @param principal      user id
   * @param previousGroups groups of the previous login, read before the store was
   *                       overwritten
   * @param currentGroups  sanitized groups of the current login
   */
  public void sync(String principal, Set<String> previousGroups, Set<String> currentGroups) {
    try {
      // group management requires elevated privileges, but during the login the
      // subject is not yet authenticated
      administrationContext.runAsAdmin(() -> {
        for (String group : currentGroups) {
          runSafely(group, () -> addMember(group, principal));
        }
        for (String group : previousGroups) {
          if (!currentGroups.contains(group)) {
            runSafely(group, () -> removeMember(group, principal));
          }
        }
      });
    } catch (RuntimeException ex) {
      LOG.error("failed to synchronize groups of user {}", principal, ex);
    }
  }

  /**
   * Group synchronization must never prevent the authentication itself, so
   * failures are logged and the remaining groups are still processed.
   */
  private void runSafely(String groupName, Runnable action) {
    try {
      action.run();
    } catch (RuntimeException ex) {
      LOG.error("failed to synchronize group {}, login continues without it", groupName, ex);
    }
  }

  /**
   * Names are already mapped to valid ones by {@link GroupNameSanitizer}, this
   * is only a last guard so that an unexpected name cannot break the login with
   * a constraint violation.
   */
  private boolean isValidGroupName(String groupName) {
    if (ValidationUtil.isNameValid(groupName)) {
      return true;
    }
    LOG.warn("skipping group '{}', because it is not a valid scm group name", groupName);
    return false;
  }

  /**
   * Creates the group with the user as first member if it does not exist yet,
   * otherwise adds the user if necessary.
   */
  private void addMember(String groupName, String principal) {
    if (!isValidGroupName(groupName)) {
      return;
    }
    Group group = groupManager.get(groupName);
    if (group == null) {
      LOG.info("creating group {} from oauth2 group claim with member {}", groupName, principal);
      Group newGroup = new Group(GROUP_TYPE, groupName, principal);
      newGroup.setDescription(GROUP_DESCRIPTION);
      groupManager.create(newGroup);
    } else if (group.isExternal()) {
      LOG.debug("skipping external group {}", groupName);
    } else if (!group.isMember(principal)) {
      LOG.info("adding user {} to group {}", principal, groupName);
      group.add(principal);
      groupManager.modify(group);
    }
  }

  /**
   * Removes the membership of a group which is no longer part of the claim. The
   * group itself stays, together with the permissions granted to it.
   */
  private void removeMember(String groupName, String principal) {
    if (!isValidGroupName(groupName)) {
      return;
    }
    Group group = groupManager.get(groupName);
    if (group == null || group.isExternal()) {
      return;
    }
    if (group.isMember(principal)) {
      LOG.info("removing user {} from group {}", principal, groupName);
      group.remove(principal);
      // groups are never deleted, even if the last member was removed
      groupManager.modify(group);
    }
  }
}
