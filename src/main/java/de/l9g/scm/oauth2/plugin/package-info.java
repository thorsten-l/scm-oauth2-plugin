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

/**
 * OAuth2/OIDC authentication for SCM-Manager (authorization code flow with PKCE).
 *
 * <h2>How the plugin is wired into SCM-Manager</h2>
 *
 * There is no explicit registration anywhere: SCM-Manager scans the plugin for
 * classes annotated with {@code @Extension} and for JAX-RS resources, everything
 * else is instantiated by guice. The entry points are:
 *
 * <ul>
 *   <li>{@link de.l9g.scm.oauth2.plugin.OAuth2AuthenticationResource} - the two
 *       http endpoints of the flow, {@code /api/v2/oauth2/auth} and
 *       {@code /api/v2/oauth2/auth/callback}</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.OAuth2Realm} - shiro realm, turns an
 *       {@link de.l9g.scm.oauth2.plugin.OAuth2Token} into an authenticated
 *       subject</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.OAuth2GroupResolver} - tells the core
 *       which groups a user belongs to, used for authorization</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.ForceOAuth2LoginFilter} - servlet filter
 *       for the optional forced single sign on</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.AfterLogoutRedirectToIdp} - hook of the
 *       core logout resource, performs the RP-initiated logout</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.IndexConfigurationEnricher} - adds the
 *       links {@code oauth2Login} and {@code oauth2Config} to the index resource,
 *       which is how the react frontend learns that the plugin is configured</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.OAuth2ExternalAuthenticationAvailableNotifier}
 *       - lets the core know that users may exist without a local password</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.config.ConfigurationResource} - REST
 *       endpoint of the administration ui</li>
 * </ul>
 *
 * <h2>Login flow</h2>
 *
 * <ol>
 *   <li>The browser calls {@code GET /api/v2/oauth2/auth?from=/repos} (button on
 *       the login page, or a redirect of the
 *       {@link de.l9g.scm.oauth2.plugin.ForceOAuth2LoginFilter}).</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.StateStore} creates an
 *       {@link de.l9g.scm.oauth2.plugin.AuthorizationRequest}: a random state, a
 *       {@link de.l9g.scm.oauth2.plugin.Pkce} verifier and the sanitized target
 *       url. The state is additionally written to the browser as
 *       {@link de.l9g.scm.oauth2.plugin.StateCookie}.</li>
 *   <li>The response is a redirect to the authorization endpoint, which
 *       {@link de.l9g.scm.oauth2.plugin.EndpointResolver} either takes from the
 *       manual configuration or from the discovery document fetched by
 *       {@link de.l9g.scm.oauth2.plugin.DiscoveryClient}.</li>
 *   <li>The identity provider authenticates the user and redirects back to
 *       {@code /api/v2/oauth2/auth/callback?code=...&amp;state=...}.</li>
 *   <li>The callback verifies that the state matches the state cookie of this
 *       browser and consumes it (single use), then hands the authorization code
 *       to {@link de.l9g.scm.oauth2.plugin.LoginHandler} as
 *       {@link de.l9g.scm.oauth2.plugin.OAuth2Token}.</li>
 *   <li>{@code subject.login(token)} ends up in
 *       {@link de.l9g.scm.oauth2.plugin.OAuth2Realm}, which delegates to
 *       {@link de.l9g.scm.oauth2.plugin.AuthenticationInfoBuilder} - the place
 *       where everything comes together (see below).</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.LoginHandler} issues the access token
 *       cookie of SCM-Manager, the callback redirects to the target url and
 *       invalidates the state cookie.</li>
 * </ol>
 *
 * <h2>What happens on every login</h2>
 *
 * {@link de.l9g.scm.oauth2.plugin.AuthenticationInfoBuilder} is the single place
 * which orchestrates the following steps, so start reading there:
 *
 * <ol>
 *   <li>{@link de.l9g.scm.oauth2.plugin.OAuth2RestClient} exchanges the
 *       authorization code for tokens and fetches the userinfo claims.</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.UserInfoMapper} maps the claims to a
 *       user, {@link de.l9g.scm.oauth2.plugin.UserMigration} merges it with an
 *       account which may already exist under the same name.</li>
 *   <li>The groups of the claim plus the roles read by
 *       {@link de.l9g.scm.oauth2.plugin.AccessTokenRoleReader} are passed through
 *       {@link de.l9g.scm.oauth2.plugin.GroupNameSanitizer} and stored in the
 *       {@link de.l9g.scm.oauth2.plugin.GroupStore} (the source of the
 *       {@link de.l9g.scm.oauth2.plugin.OAuth2GroupResolver}).</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.GroupSynchronizer} creates missing groups
 *       and updates the memberships,
 *       {@link de.l9g.scm.oauth2.plugin.AdminGroupSynchronizer} assigns or
 *       revokes the global administrator permission.</li>
 *   <li>The id token is kept in the
 *       {@link de.l9g.scm.oauth2.plugin.IdTokenStore} for the logout.</li>
 * </ol>
 *
 * <h2>Logout flow</h2>
 *
 * The core logout resource logs the subject out and then asks every
 * {@code LogoutRedirection} extension for a redirect target.
 * {@link de.l9g.scm.oauth2.plugin.AfterLogoutRedirectToIdp} builds the url of
 * the end session endpoint with {@code id_token_hint} (taken from the
 * {@link de.l9g.scm.oauth2.plugin.IdTokenStore}) and
 * {@code post_logout_redirect_uri}, so the identity provider terminates its own
 * session without a confirmation prompt and sends the browser back.
 *
 * <h2>Configuration</h2>
 *
 * {@link de.l9g.scm.oauth2.plugin.OAuth2Configuration} is the single
 * configuration object of the plugin, persisted as xml by
 * {@link de.l9g.scm.oauth2.plugin.OAuth2Context} and edited through the
 * {@code de.l9g.scm.oauth2.plugin.config} package. Read it with
 * {@code context.get()}; it is never {@code null}, an unconfigured instance
 * simply returns the defaults with {@code enabled == false}.
 *
 * <h2>Conventions worth knowing</h2>
 *
 * <ul>
 *   <li><b>Elevated privileges:</b> while a login is processed the subject is not
 *       authenticated yet, so every access to users, groups or permissions runs
 *       inside {@code AdministrationContext.runAsAdmin}.</li>
 *   <li><b>Failures:</b> anything which is not the authentication itself (group
 *       synchronization, admin permission, logout hint) must never break the
 *       login, therefore those parts log and continue.</li>
 *   <li><b>Error responses:</b> values received from the identity provider are
 *       only written to the log, never reflected to the browser.</li>
 *   <li><b>In memory state:</b> {@link de.l9g.scm.oauth2.plugin.StateStore} and
 *       {@link de.l9g.scm.oauth2.plugin.IdTokenStore} are deliberately not
 *       persisted and therefore not cluster wide; a restart only means that a
 *       running login has to be repeated and that a logout happens without
 *       hint.</li>
 * </ul>
 */
package de.l9g.scm.oauth2.plugin;
