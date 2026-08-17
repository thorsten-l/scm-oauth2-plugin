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

import jakarta.inject.Inject;
import sonia.scm.plugin.Extension;
import sonia.scm.user.ExternalAuthenticationAvailableNotifier;

/**
 * Tells the core that an external authentication is available. The core uses this
 * to adapt its user administration: creating a user without a password is only
 * offered if some plugin answers {@code true} here.
 */
@Extension
public class OAuth2ExternalAuthenticationAvailableNotifier implements ExternalAuthenticationAvailableNotifier {

  private final OAuth2Context context;

  @Inject
  public OAuth2ExternalAuthenticationAvailableNotifier(OAuth2Context context) {
    this.context = context;
  }

  @Override
  public boolean isExternalAuthenticationAvailable() {
    return context.get().isEnabled();
  }
}
