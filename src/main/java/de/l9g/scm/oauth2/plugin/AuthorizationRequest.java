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

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * A pending authorization request: the state which is handed to the identity
 * provider, the pkce verifier and the nonce belonging to it and the url the user
 * should be redirected to after a successful login.
 *
 * <p>The three random values have different jobs: the state protects the callback
 * against csrf, the pkce verifier binds the authorization code to this request, and
 * the nonce binds the id token to this login.
 */
@Getter
@AllArgsConstructor
public class AuthorizationRequest {

  private final String state;
  private final String codeVerifier;
  private final String nonce;
  private final String redirectUrl;

}
