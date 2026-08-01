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

import com.google.inject.AbstractModule;
import org.mapstruct.factory.Mappers;
import sonia.scm.plugin.Extension;

@Extension
public class ConfigurationModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(ConfigurationMapper.class).to(Mappers.getMapper(ConfigurationMapper.class).getClass());
  }
}
