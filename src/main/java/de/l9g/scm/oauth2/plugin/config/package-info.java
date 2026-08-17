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
 * REST api of the administration ui, {@code /api/v2/oauth2/configuration}.
 *
 * <p>The pieces follow the usual SCM-Manager pattern for a plugin configuration:
 *
 * <ul>
 *   <li>{@link de.l9g.scm.oauth2.plugin.config.ConfigurationResource} - the
 *       JAX-RS resource with the {@code GET} and {@code PUT} methods, protected
 *       by the permissions {@code configuration:read:oauth2} and
 *       {@code configuration:write:oauth2}</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.config.ConfigurationDto} - hal
 *       representation of {@code OAuth2Configuration} with the {@code self} and
 *       {@code update} links</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.config.ConfigurationMapper} - mapstruct
 *       mapper between entity and dto, the implementation is generated at build
 *       time</li>
 *   <li>{@link de.l9g.scm.oauth2.plugin.config.ConfigurationModule} - guice
 *       module which binds the mapper to the generated implementation</li>
 * </ul>
 *
 * <p>Two details differ from a plain crud resource: the client secret is write
 * only (never returned, an empty value on update keeps the stored one) and the
 * endpoint urls are validated, because the server itself requests them.
 */
package de.l9g.scm.oauth2.plugin.config;
