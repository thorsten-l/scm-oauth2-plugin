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

import sonia.scm.config.ConfigurationPermissions;
import sonia.scm.store.ConfigurationStore;
import sonia.scm.store.ConfigurationStoreFactory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Access to the persisted {@link OAuth2Configuration}. Every class which needs
 * configuration values injects this context and calls {@link #get()} instead of
 * caching the configuration, so a change in the administration ui takes effect
 * immediately.
 *
 * <p>The configuration is stored by the core as
 * {@code config/oauth2.xml} inside the home directory of SCM-Manager.
 */
@Singleton
public class OAuth2Context {

  private final ConfigurationStore<OAuth2Configuration> store;

  @Inject
  public OAuth2Context(ConfigurationStoreFactory storeFactory) {
    this.store = storeFactory.withType(OAuth2Configuration.class).withName(Constants.NAME).build();
  }

  /**
   * Persists the configuration.
   *
   * @param configuration new configuration
   * @throws org.apache.shiro.authz.AuthorizationException if the current user
   *         lacks the permission {@code configuration:write:oauth2}
   */
  public void set(OAuth2Configuration configuration) {
    ConfigurationPermissions.write(Constants.NAME).check();
    store.set(configuration);
  }

  /**
   * Returns the current configuration, never {@code null}. As long as nothing was
   * saved, a fresh instance with the defaults and {@code enabled == false} is
   * returned, so callers do not need a null check.
   *
   * <p>Deliberately without a permission check: the plugin itself has to read the
   * configuration during an anonymous login.
   *
   * @return current configuration
   */
  public OAuth2Configuration get() {
    OAuth2Configuration configuration = store.get();
    if (configuration != null) {
      return configuration;
    }
    return new OAuth2Configuration();
  }
}
