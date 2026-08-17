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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import de.l9g.scm.oauth2.plugin.config.ConfigurationResource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;
import sonia.scm.config.ConfigurationPermissions;
import sonia.scm.plugin.Extension;
import sonia.scm.user.User;
import sonia.scm.web.JsonEnricherBase;
import sonia.scm.web.JsonEnricherContext;

import jakarta.inject.Inject;
import jakarta.inject.Provider;

import static java.util.Collections.singletonMap;
import static sonia.scm.web.VndMediaType.INDEX;

/**
 * Adds the links of the plugin to the index resource ({@code /api/v2/}). This is
 * the only channel through which the react frontend learns about the plugin: it
 * renders a login button if {@code oauth2Login} is present and shows the navigation
 * entry of the configuration if {@code oauth2Config} is present.
 *
 * <p>Because the links are permission and state dependent, the ui does not need any
 * logic of its own - what must not be visible simply has no link.
 */
@Extension
public class IndexConfigurationEnricher extends JsonEnricherBase {

  private final Provider<ScmPathInfoStore> scmPathInfoStore;
  private final OAuth2Context oauth2Context;

  @Inject
  public IndexConfigurationEnricher(Provider<ScmPathInfoStore> scmPathInfoStore, ObjectMapper objectMapper, OAuth2Context oauth2Context) {
    super(objectMapper);
    this.scmPathInfoStore = scmPathInfoStore;
    this.oauth2Context = oauth2Context;
  }

  /**
   * @param context response of the resource which is currently being enriched,
   *                every json response passes by here
   */
  @Override
  public void enrich(JsonEnricherContext context) {
    if (resultHasMediaType(INDEX, context)) {
      JsonNode links = context.getResponseEntity().get("_links");

      // link to the configuration only for administrators
      if (ConfigurationPermissions.read().isPermitted(Constants.NAME)) {
        String configUrl = new LinkBuilder(scmPathInfoStore.get().get(), ConfigurationResource.class)
          .method("get")
          .parameters()
          .href();

        JsonNode configRefNode = createObject(singletonMap("href", value(configUrl)));

        addPropertyNode(links, "oauth2Config", configRefNode);
      }

      // the login link is offered as long as nobody is logged in through an
      // external authentication yet; the name is used as the label of the button
      if (isOAuth2AuthenticationEnabled() && !isExternalUserAuthenticated()) {
        String loginUrl = new LinkBuilder(scmPathInfoStore.get().get(), OAuth2AuthenticationResource.class)
          .method("login")
          .parameters()
          .href();

        JsonNode loginNode = createObject(ImmutableMap.of(
          "href", value(loginUrl),
          "name", value(getProviderName())
        ));

        addPropertyNode(links, "oauth2Login", loginNode);
      }

    }
  }

  private boolean isOAuth2AuthenticationEnabled() {
    return oauth2Context.get().isEnabled();
  }

  /**
   * The provider name is mandatory in the configuration, but an instance which was
   * configured before that rule existed may still be missing it.
   */
  private String getProviderName() {
    String providerName = oauth2Context.get().getProviderName();
    return Strings.isNullOrEmpty(providerName) ? "OAuth2" : providerName;
  }

  /**
   * Someone who is already logged in externally does not need a login button; a
   * locally authenticated user may still switch to the identity provider.
   */
  private boolean isExternalUserAuthenticated() {
    Subject subject = SecurityUtils.getSubject();
    if (subject.isAuthenticated()) {
      User user = subject.getPrincipals().oneByType(User.class);
      return user.isExternal();
    }
    return false;
  }

}
