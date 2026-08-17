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

import com.google.common.collect.ImmutableSet;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import sonia.scm.store.DataStore;
import sonia.scm.store.DataStoreFactory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Set;

/**
 * Stores the group names of the last login per user. It is the source of the
 * {@link OAuth2GroupResolver} and therefore the basis of every authorization by
 * group.
 *
 * <p>The store is needed because the claims are only available during the login,
 * while authorization happens on every request. It is persisted by the core below
 * {@code var/data/oauth2Groups} (one xml file per user), so a restart does not
 * cost anyone their permissions.
 *
 * <p>The names in here are already sanitized, see {@link GroupNameSanitizer}.
 */
@Singleton
public class GroupStore {

  private static final String STORE_NAME = "oauth2Groups";
  private final DataStore<Groups> store;

  @Inject
  public GroupStore(DataStoreFactory factory) {
    this.store = factory.withType(Groups.class).withName(STORE_NAME).build();
  }

  /**
   * @param principal user id
   * @return groups of the last login, empty if the user never logged in via oauth2
   */
  public Set<String> get(String principal) {
    Groups groups = store.get(principal);
    return groups != null ? groups.groups : ImmutableSet.of();
  }

  /**
   * Replaces the groups of a user; the previous entry is not merged.
   *
   * @param principal user id
   * @param groups    sanitized group names of the current login
   */
  public void put(String principal, Set<String> groups) {
    store.put(principal, new Groups(groups));
  }

  /**
   * Jaxb wrapper, the data store needs a class it can marshal - a bare
   * {@code Set} would not work.
   */
  @AllArgsConstructor
  @NoArgsConstructor
  @XmlRootElement
  @XmlAccessorType(XmlAccessType.FIELD)
  static class Groups {
    @XmlElement(name = "name")
    Set<String> groups;
  }
}
