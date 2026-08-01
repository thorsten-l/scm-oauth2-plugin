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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.security.AssignedPermission;
import sonia.scm.security.SecuritySystem;
import sonia.scm.web.security.AdministrationContext;
import sonia.scm.web.security.PrivilegedAction;

import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminGroupSynchronizerTest {

  private static final String PRINCIPAL = "trillian";

  @Mock
  private OAuth2Context context;

  @Mock
  private SecuritySystem securitySystem;

  @Mock
  private AdministrationContext administrationContext;

  private final OAuth2Configuration configuration = new OAuth2Configuration();

  private AdminGroupSynchronizer synchronizer;

  @BeforeEach
  void setUpSynchronizer() {
    synchronizer = new AdminGroupSynchronizer(context, securitySystem, administrationContext);
    lenient().when(context.get()).thenReturn(configuration);
    // execute privileged actions immediately
    lenient().doAnswer(invocation -> {
      invocation.getArgument(0, PrivilegedAction.class).run();
      return null;
    }).when(administrationContext).runAsAdmin(any(PrivilegedAction.class));
  }

  @Test
  void shouldDoNothingWithoutConfiguredAdminGroup() {
    configuration.setAdminGroup("");

    synchronizer.sync(PRINCIPAL, Set.of("scmadmin"));

    verifyNoInteractions(securitySystem);
  }

  @Test
  void shouldUseScmadminAsDefaultAdminGroup() {
    assertThat(new OAuth2Configuration().getAdminGroup()).isEqualTo("scmadmin");
  }

  @Test
  void shouldAssignAdminPermission() {
    configuration.setAdminGroup("scmadmin");
    when(securitySystem.getPermissions(any())).thenReturn(emptyList());

    synchronizer.sync(PRINCIPAL, Set.of("scmadmin", "heartOfGold"));

    ArgumentCaptor<AssignedPermission> captor = ArgumentCaptor.forClass(AssignedPermission.class);
    verify(securitySystem).addPermission(captor.capture());
    assertThat(captor.getValue().getName()).isEqualTo(PRINCIPAL);
    assertThat(captor.getValue().getPermission().getValue()).isEqualTo("*");
    assertThat(captor.getValue().isGroupPermission()).isFalse();
  }

  @Test
  void shouldNotAssignAdminPermissionTwice() {
    configuration.setAdminGroup("scmadmin");
    when(securitySystem.getPermissions(any())).thenReturn(List.of(new AssignedPermission(PRINCIPAL, "*")));

    synchronizer.sync(PRINCIPAL, Set.of("scmadmin"));

    verify(securitySystem, never()).addPermission(any());
    verify(securitySystem, never()).deletePermission(any());
  }

  @Test
  void shouldRevokeAdminPermission() {
    configuration.setAdminGroup("scmadmin");
    AssignedPermission assigned = new AssignedPermission(PRINCIPAL, "*");
    when(securitySystem.getPermissions(any())).thenReturn(List.of(assigned));

    synchronizer.sync(PRINCIPAL, Set.of("heartOfGold"));

    verify(securitySystem).deletePermission(assigned);
    verify(securitySystem, never()).addPermission(any());
  }

  @Test
  void shouldNotRevokeAnythingIfNoPermissionAssigned() {
    configuration.setAdminGroup("scmadmin");
    when(securitySystem.getPermissions(any())).thenReturn(emptyList());

    synchronizer.sync(PRINCIPAL, Set.of("heartOfGold"));

    verify(securitySystem, never()).addPermission(any());
    verify(securitySystem, never()).deletePermission(any());
  }

  @Test
  void shouldFilterForUserAdminPermission() {
    configuration.setAdminGroup("scmadmin");
    when(securitySystem.getPermissions(any())).thenReturn(emptyList());

    synchronizer.sync(PRINCIPAL, Set.of("scmadmin"));

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Predicate<AssignedPermission>> captor = ArgumentCaptor.forClass(Predicate.class);
    verify(securitySystem).getPermissions(captor.capture());
    Predicate<AssignedPermission> predicate = captor.getValue();

    assertThat(predicate.test(new AssignedPermission(PRINCIPAL, "*"))).isTrue();
    assertThat(predicate.test(new AssignedPermission(PRINCIPAL, "repository:read:*"))).isFalse();
    assertThat(predicate.test(new AssignedPermission("dent", "*"))).isFalse();
    assertThat(predicate.test(new AssignedPermission(PRINCIPAL, true, "*"))).isFalse();
  }
}
