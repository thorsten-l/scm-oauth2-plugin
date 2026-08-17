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

/**
 * The complete configuration of the plugin, persisted as {@code config/oauth2.xml}
 * by {@link OAuth2Context} and edited through the administration ui.
 *
 * <p>The defaults assigned here are what an administrator sees when the
 * configuration page is opened for the first time; they are tailored to a
 * keycloak installation with the standard protocol mappers.
 *
 * <p>Two jaxb details are easy to get wrong:
 *
 * <ul>
 *   <li>{@code XmlAccessType.FIELD} is mandatory. With the default property
 *       access jaxb sees the field and the lombok getter of
 *       {@code clientSecret} as two properties and the deployment fails with an
 *       {@code IllegalAnnotationsException}.</li>
 *   <li>New fields must not be mandatory. Reading an older configuration file
 *       leaves them at their default, there is no migration step.</li>
 * </ul>
 */
@Getter
@Setter
@NoArgsConstructor
@XmlRootElement(name = "oauth2")
// field access is required, so that the adapter of the client secret does not
// collide with the generated getter
@XmlAccessorType(XmlAccessType.FIELD)
public class OAuth2Configuration {

  /**
   * Display name of the identity provider, shown on the login button as
   * "Login with ...". Mandatory as soon as the plugin is enabled.
   */
  private String providerName;

  /**
   * Issuer url or complete url of the discovery document. If set, the four
   * endpoints below are ignored and resolved by the {@link EndpointResolver}
   * instead.
   */
  private String discoveryUrl;

  private String authorizationUrl;
  private String tokenUrl;
  private String userinfoUrl;

  /**
   * End session endpoint for the RP-initiated logout. Optional, without it
   * {@link #ssoLogout} cannot do anything.
   */
  private String endSessionUrl;

  /**
   * Url of the json web key set, needed to verify the signatures of id token and
   * access token. Only relevant without a discovery url, which delivers the key set
   * url itself. Without it no token is verified and therefore none is used - see
   * {@link TokenVerifier}.
   */
  private String jwksUrl;

  private String clientId;

  /**
   * Stored encrypted. Values which were written as plain text by an earlier
   * version are still read correctly and encrypted on the next save.
   */
  @XmlJavaTypeAdapter(XmlEncryptionAdapter.class)
  private String clientSecret;

  /**
   * Space separated scopes of the authorization request. {@code openid} is
   * required for OIDC, the other two provide name and mail claim.
   */
  private String scopes = "openid profile email";

  /**
   * Claim of the userinfo response which becomes the user id in SCM-Manager. It
   * has to be stable, because every permission is bound to it. Falls back to the
   * {@code sub} claim if the configured one is missing.
   */
  private String usernameAttribute = "preferred_username";
  private String displayNameAttribute = "name";
  private String mailAttribute = "email";

  /**
   * Claim which contains the group names, a single value or an array.
   */
  private String groupAttribute = "groups";

  /**
   * Group which grants the global administrator permission. If a user has this
   * group, the permission is assigned on login, otherwise it is revoked again.
   * An empty value switches the whole mechanism off.
   */
  private String adminGroup = "scmadmin";

  /**
   * Reads additional groups from the access token, e.g. the keycloak realm
   * roles, which are not part of the userinfo response.
   */
  private boolean importRealmRoles = false;

  /**
   * Dot separated path inside the access token payload which holds the roles,
   * see {@link AccessTokenRoleReader}.
   */
  private String realmRolesPath = "realm_access.roles";

  /**
   * Redirects unauthenticated browser requests to the identity provider, so the
   * login page with username and password is no longer reachable.
   */
  private boolean forceLogin = false;

  /**
   * Terminates the session at the identity provider as well when a user logs out
   * of SCM-Manager (RP-initiated logout).
   */
  private boolean ssoLogout = false;

  /**
   * Allows the identity provider to take over accounts which can still be used
   * for a local password login. Users of other external authentications (ldap,
   * cas) are migrated without this flag.
   */
  private boolean migrateLocalUsers = false;

  /**
   * Master switch. As long as this is {@code false} the login endpoint answers
   * with 404, no login button is offered and neither the forced login nor the sso
   * logout do anything.
   */
  private boolean enabled;

}
