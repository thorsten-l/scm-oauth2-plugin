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

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import sonia.scm.xml.XmlEncryptionAdapter;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@Getter
@Setter
@NoArgsConstructor
@XmlRootElement(name = "oauth2")
// field access is required, so that the adapter of the client secret does not
// collide with the generated getter
@XmlAccessorType(XmlAccessType.FIELD)
public class OAuth2Configuration {

  private String providerName;

  private String discoveryUrl;

  private String authorizationUrl;
  private String tokenUrl;
  private String userinfoUrl;
  private String endSessionUrl;

  private String clientId;

  /**
   * Stored encrypted. Values which were written as plain text by an earlier
   * version are still read correctly and encrypted on the next save.
   */
  @XmlJavaTypeAdapter(XmlEncryptionAdapter.class)
  private String clientSecret;
  private String scopes = "openid profile email";

  private String usernameAttribute = "preferred_username";
  private String displayNameAttribute = "name";
  private String mailAttribute = "email";
  private String groupAttribute = "groups";
  private String adminGroup = "scmadmin";

  private boolean forceLogin = false;
  private boolean ssoLogout = false;

  private boolean enabled;

}
