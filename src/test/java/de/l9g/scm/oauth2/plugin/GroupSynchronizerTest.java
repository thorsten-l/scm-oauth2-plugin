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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.group.Group;
import sonia.scm.group.GroupManager;
import sonia.scm.web.security.AdministrationContext;
import sonia.scm.web.security.PrivilegedAction;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests the synchronization of groups and memberships: creating missing groups,
 * adding and removing members, keeping empty groups and skipping external ones.
 * The second half is about robustness - a failure of a single group, an invalid name
 * or a failing administration context must never fail the login.
 */
@ExtendWith(MockitoExtension.class)
class GroupSynchronizerTest {

  private static final String PRINCIPAL = "trillian";

  @Mock
  private GroupManager groupManager;

  @Mock
  private AdministrationContext administrationContext;

  private GroupSynchronizer synchronizer;

  @BeforeEach
  void setUpSynchronizer() {
    synchronizer = new GroupSynchronizer(groupManager, administrationContext);
    // execute privileged actions immediately
    lenient().doAnswer(invocation -> {
      invocation.getArgument(0, PrivilegedAction.class).run();
      return null;
    }).when(administrationContext).runAsAdmin(any(PrivilegedAction.class));
  }

  @Test
  void shouldCreateMissingGroupWithMember() {
    when(groupManager.get("heartOfGold")).thenReturn(null);

    synchronizer.sync(PRINCIPAL, Set.of(), Set.of("heartOfGold"));

    ArgumentCaptor<Group> captor = ArgumentCaptor.forClass(Group.class);
    verify(groupManager).create(captor.capture());
    Group created = captor.getValue();
    assertThat(created.getName()).isEqualTo("heartOfGold");
    assertThat(created.getMembers()).containsExactly(PRINCIPAL);
    assertThat(created.getType()).isEqualTo("xml");
  }

  @Test
  void shouldAddMemberToExistingGroup() {
    Group group = new Group("xml", "heartOfGold", "dent");
    when(groupManager.get("heartOfGold")).thenReturn(group);

    synchronizer.sync(PRINCIPAL, Set.of(), Set.of("heartOfGold"));

    verify(groupManager).modify(group);
    assertThat(group.getMembers()).containsExactlyInAnyOrder("dent", PRINCIPAL);
  }

  @Test
  void shouldNotModifyGroupIfAlreadyMember() {
    Group group = new Group("xml", "heartOfGold", PRINCIPAL);
    when(groupManager.get("heartOfGold")).thenReturn(group);

    synchronizer.sync(PRINCIPAL, Set.of("heartOfGold"), Set.of("heartOfGold"));

    verify(groupManager, never()).create(any());
    verify(groupManager, never()).modify(any());
  }

  @Test
  void shouldRemoveMemberFromDroppedGroup() {
    Group group = new Group("xml", "heartOfGold", PRINCIPAL, "dent");
    when(groupManager.get("heartOfGold")).thenReturn(group);

    synchronizer.sync(PRINCIPAL, Set.of("heartOfGold"), Set.of());

    verify(groupManager).modify(group);
    assertThat(group.getMembers()).containsExactly("dent");
  }

  @Test
  void shouldNotDeleteEmptyGroup() {
    Group group = new Group("xml", "heartOfGold", PRINCIPAL);
    when(groupManager.get("heartOfGold")).thenReturn(group);

    synchronizer.sync(PRINCIPAL, Set.of("heartOfGold"), Set.of());

    verify(groupManager).modify(group);
    verify(groupManager, never()).delete(any());
    assertThat(group.getMembers()).isEmpty();
  }

  @Test
  void shouldSkipExternalGroups() {
    Group external = new Group("xml", "heartOfGold");
    external.setExternal(true);
    when(groupManager.get("heartOfGold")).thenReturn(external);

    synchronizer.sync(PRINCIPAL, Set.of(), Set.of("heartOfGold"));

    verify(groupManager, never()).create(any());
    verify(groupManager, never()).modify(any());
  }

  @Test
  void shouldIgnoreDroppedGroupWhichNoLongerExists() {
    when(groupManager.get("heartOfGold")).thenReturn(null);

    synchronizer.sync(PRINCIPAL, Set.of("heartOfGold"), Set.of());

    verify(groupManager, never()).create(any());
    verify(groupManager, never()).modify(any());
  }

  @ParameterizedTest
  @ValueSource(strings = {"/developers", "some/group", "with space ", "a:b", "a?b", "a#b", "a&b", "a=b", "a%b", "a\\b"})
  void shouldSkipGroupNamesWhichAreInvalidForScm(String invalidName) {
    synchronizer.sync(PRINCIPAL, Set.of(), Set.of(invalidName));

    verify(groupManager, never()).get(any());
    verify(groupManager, never()).create(any());
    verify(groupManager, never()).modify(any());
  }

  @Test
  void shouldSkipInvalidGroupNameOnRemoval() {
    synchronizer.sync(PRINCIPAL, Set.of("/developers"), Set.of());

    verify(groupManager, never()).get(any());
    verify(groupManager, never()).modify(any());
  }

  @Test
  void shouldSynchronizeValidGroupsEvenIfAnotherOneIsInvalid() {
    when(groupManager.get("heartOfGold")).thenReturn(null);

    synchronizer.sync(PRINCIPAL, Set.of(), Set.of("/invalid", "heartOfGold"));

    verify(groupManager).create(any());
  }

  @Test
  void shouldNotFailLoginIfGroupCreationFails() {
    when(groupManager.get("heartOfGold")).thenReturn(null);
    when(groupManager.create(any())).thenThrow(new IllegalStateException("group could not be created"));

    // must not propagate, otherwise the login of the user would fail
    synchronizer.sync(PRINCIPAL, Set.of(), Set.of("heartOfGold"));

    verify(groupManager).create(any());
  }

  @Test
  void shouldSynchronizeRemainingGroupsIfOneFails() {
    Group second = new Group("xml", "restaurant", "dent");
    when(groupManager.get("heartOfGold")).thenReturn(null);
    when(groupManager.get("restaurant")).thenReturn(second);
    when(groupManager.create(any())).thenThrow(new IllegalStateException("group could not be created"));

    synchronizer.sync(PRINCIPAL, Set.of(), Set.of("heartOfGold", "restaurant"));

    verify(groupManager).modify(second);
    assertThat(second.getMembers()).contains(PRINCIPAL);
  }

  @Test
  void shouldNotFailLoginIfAdministrationContextFails() {
    doThrow(new IllegalStateException("no admin context"))
      .when(administrationContext).runAsAdmin(any(PrivilegedAction.class));

    synchronizer.sync(PRINCIPAL, Set.of(), Set.of("heartOfGold"));

    verify(groupManager, never()).create(any());
  }
}
