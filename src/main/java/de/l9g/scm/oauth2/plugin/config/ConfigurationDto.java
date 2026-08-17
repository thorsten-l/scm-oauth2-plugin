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

package de.l9g.scm.oauth2.plugin.config;

import de.otto.edison.hal.HalRepresentation;
import de.otto.edison.hal.Links;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Transport format of the configuration. Mirrors
 * {@code OAuth2Configuration} field by field, with two additions: the hal links
 * ({@code self} and, if permitted, {@code update}) added by the
 * {@link ConfigurationMapper}, and the read only flag {@link #clientSecretSet}.
 *
 * <p>New configuration fields have to be added here as well, otherwise they never
 * reach the ui - the mapper maps by name.
 */
@Getter
@Setter
@NoArgsConstructor
public class ConfigurationDto extends HalRepresentation {

  private String providerName;

  private String discoveryUrl;

  private String authorizationUrl;
  private String tokenUrl;
  private String userinfoUrl;
  private String endSessionUrl;
  private String jwksUrl;

  private String clientId;

  /**
   * Write only: the get endpoint never returns the stored secret, an empty
   * value on update keeps it unchanged.
   */
  private String clientSecret;

  /**
   * Read only hint for the ui whether a secret is stored.
   */
  private boolean clientSecretSet;
  private String scopes;

  private String usernameAttribute;
  private String displayNameAttribute;
  private String mailAttribute;
  private String groupAttribute;
  private String adminGroup;

  private boolean importRealmRoles;
  private String realmRolesPath;

  private boolean forceLogin;
  private boolean ssoLogout;
  private boolean migrateLocalUsers;

  private boolean enabled;

  /**
   * Only overridden to widen the visibility, so the mapper of this package can add
   * the links.
   */
  @Override
  @SuppressWarnings("squid:S1185") // We want to have this method available in this package
  protected HalRepresentation add(Links links) {
    return super.add(links);
  }

}
