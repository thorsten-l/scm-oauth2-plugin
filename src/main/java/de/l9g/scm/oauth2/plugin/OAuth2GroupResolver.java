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

import sonia.scm.group.GroupResolver;
import sonia.scm.plugin.Extension;

import jakarta.inject.Inject;
import java.util.Set;

import static java.util.Collections.emptySet;

/**
 * Tells SCM-Manager which groups a user belongs to. The core asks every registered
 * resolver while it builds the authorization info of a request, and the results of
 * all resolvers are combined.
 *
 * <p>The answer comes from the {@link GroupStore}, which was filled during the
 * login. Groups therefore work for every kind of request, including git over http
 * with an api key, where no claims are available.
 */
@Extension
public class OAuth2GroupResolver implements GroupResolver {

  private final GroupStore store;

  @Inject
  public OAuth2GroupResolver(GroupStore store) {
    this.store = store;
  }

  /**
   * @param principal user id
   * @return groups of the last oauth2 login, never {@code null}
   */
  @Override
  public Set<String> resolve(String principal) {
    Set<String> groups = store.get(principal);
    if (groups == null) {
      return emptySet();
    }
    return groups;
  }
}
