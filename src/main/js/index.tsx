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

import { Links } from "@scm-manager/ui-types";
import { ConfigurationBinder as cfgBinder } from "@scm-manager/ui-components";
import { binder } from "@scm-manager/ui-extensions";
import GlobalOAuth2Configuration from "./GlobalOAuth2Configuration";
import OAuth2LoginLink from "./OAuth2LoginLink";
import OAuth2LoginForm from "./OAuth2LoginForm";

cfgBinder.bindGlobal("/oauth2", "scm-oauth2-plugin.nav-link", "oauth2Config", GlobalOAuth2Configuration);
binder.bind("primary-navigation.login", OAuth2LoginLink, props => "oauth2Login" in (props?.links as Links));
binder.bind("login.form", OAuth2LoginForm);
