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

  @Override
  public void enrich(JsonEnricherContext context) {
    if (resultHasMediaType(INDEX, context)) {
      JsonNode links = context.getResponseEntity().get("_links");

      if (ConfigurationPermissions.read().isPermitted(Constants.NAME)) {
        String configUrl = new LinkBuilder(scmPathInfoStore.get().get(), ConfigurationResource.class)
          .method("get")
          .parameters()
          .href();

        JsonNode configRefNode = createObject(singletonMap("href", value(configUrl)));

        addPropertyNode(links, "oauth2Config", configRefNode);
      }

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

  private String getProviderName() {
    String providerName = oauth2Context.get().getProviderName();
    return Strings.isNullOrEmpty(providerName) ? "OAuth2" : providerName;
  }

  private boolean isExternalUserAuthenticated() {
    Subject subject = SecurityUtils.getSubject();
    if (subject.isAuthenticated()) {
      User user = subject.getPrincipals().oneByType(User.class);
      return user.isExternal();
    }
    return false;
  }

}
