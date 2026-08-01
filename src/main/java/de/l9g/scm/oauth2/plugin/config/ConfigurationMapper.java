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

import de.l9g.scm.oauth2.plugin.Constants;
import de.l9g.scm.oauth2.plugin.OAuth2Configuration;
import de.otto.edison.hal.Links;
import org.mapstruct.AfterMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;
import sonia.scm.config.ConfigurationPermissions;

import jakarta.inject.Inject;

import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;

@Mapper
public abstract class ConfigurationMapper {

  abstract OAuth2Configuration fromDto(ConfigurationDto dto);

  @Mapping(target = "attributes", ignore = true)
  @Mapping(target = "clientSecretSet", ignore = true)
  abstract ConfigurationDto toDto(OAuth2Configuration configuration);

  @Inject
  private ScmPathInfoStore scmPathInfoStore;

  @AfterMapping
  void appendLinks(@MappingTarget ConfigurationDto dto) {
    Links.Builder linksBuilder = linkingTo().self(self());
    if (ConfigurationPermissions.write(Constants.NAME).isPermitted()) {
      linksBuilder.single(link("update", update()));
    }
    dto.add(linksBuilder.build());
  }

  private String self() {
    return linkBuilder().method("get").parameters().href();
  }

  private String update() {
    return linkBuilder().method("update").parameters().href();
  }

  private LinkBuilder linkBuilder() {
    return new LinkBuilder(scmPathInfoStore.get(), ConfigurationResource.class);
  }

}
