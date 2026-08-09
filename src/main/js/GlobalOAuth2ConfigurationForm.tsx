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

import React from "react";
import { WithTranslation, withTranslation } from "react-i18next";
import { Links } from "@scm-manager/ui-types";
import { Checkbox, InputField, Subtitle } from "@scm-manager/ui-components";

type GlobalConfiguration = {
  providerName: string;
  discoveryUrl: string;
  authorizationUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  endSessionUrl: string;
  clientId: string;
  clientSecret: string;
  clientSecretSet: boolean;
  scopes: string;
  usernameAttribute: string;
  displayNameAttribute: string;
  mailAttribute: string;
  groupAttribute: string;
  adminGroup: string;
  importRealmRoles: boolean;
  realmRolesPath: string;
  forceLogin: boolean;
  ssoLogout: boolean;
  migrateLocalUsers: boolean;
  enabled: boolean;
  _links: Links;
};

type Props = WithTranslation & {
  initialConfiguration: GlobalConfiguration;
  onConfigurationChange: (p1: GlobalConfiguration, p2: boolean) => void;
};

type State = GlobalConfiguration & {
  configurationChanged?: boolean;
};

class GlobalOAuth2ConfigurationForm extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      ...props.initialConfiguration
    };
  }

  render() {
    const { t } = this.props;
    return (
      <>
        {this.renderConfigChangedNotification()}
        <Checkbox
          name="enabled"
          label={t("scm-oauth2-plugin.form.enabled")}
          helpText={t("scm-oauth2-plugin.form.enabledHelp")}
          checked={this.state.enabled}
          onChange={this.valueChangeHandler}
        />
        <Checkbox
          name="forceLogin"
          label={t("scm-oauth2-plugin.form.forceLogin")}
          helpText={t("scm-oauth2-plugin.form.forceLoginHelp")}
          checked={this.state.forceLogin}
          disabled={!this.state.enabled}
          onChange={this.valueChangeHandler}
        />
        <Checkbox
          name="ssoLogout"
          label={t("scm-oauth2-plugin.form.ssoLogout")}
          helpText={t("scm-oauth2-plugin.form.ssoLogoutHelp")}
          checked={this.state.ssoLogout}
          disabled={!this.state.enabled}
          onChange={this.valueChangeHandler}
        />
        <Checkbox
          name="migrateLocalUsers"
          label={t("scm-oauth2-plugin.form.migrateLocalUsers")}
          helpText={t("scm-oauth2-plugin.form.migrateLocalUsersHelp")}
          checked={this.state.migrateLocalUsers}
          disabled={!this.state.enabled}
          onChange={this.valueChangeHandler}
        />
        <InputField
          name="providerName"
          label={t("scm-oauth2-plugin.form.providerName")}
          helpText={t("scm-oauth2-plugin.form.providerNameHelp")}
          disabled={!this.state.enabled}
          value={this.state.providerName}
          onChange={this.valueChangeHandler}
          validationError={this.state.enabled && !this.state.providerName}
          errorMessage={t("scm-oauth2-plugin.form.providerNameRequired")}
        />
        <div>
          <Subtitle subtitle={t("scm-oauth2-plugin.form.endpoints")} />
          <InputField
            name="discoveryUrl"
            label={t("scm-oauth2-plugin.form.discoveryUrl")}
            helpText={t("scm-oauth2-plugin.form.discoveryUrlHelp")}
            disabled={!this.state.enabled}
            value={this.state.discoveryUrl}
            onChange={this.valueChangeHandler}
            type="url"
          />
          <InputField
            name="authorizationUrl"
            label={t("scm-oauth2-plugin.form.authorizationUrl")}
            helpText={t("scm-oauth2-plugin.form.authorizationUrlHelp")}
            disabled={!this.state.enabled || !!this.state.discoveryUrl}
            value={this.state.authorizationUrl}
            onChange={this.valueChangeHandler}
            type="url"
          />
          <InputField
            name="tokenUrl"
            label={t("scm-oauth2-plugin.form.tokenUrl")}
            helpText={t("scm-oauth2-plugin.form.tokenUrlHelp")}
            disabled={!this.state.enabled || !!this.state.discoveryUrl}
            value={this.state.tokenUrl}
            onChange={this.valueChangeHandler}
            type="url"
          />
          <InputField
            name="userinfoUrl"
            label={t("scm-oauth2-plugin.form.userinfoUrl")}
            helpText={t("scm-oauth2-plugin.form.userinfoUrlHelp")}
            disabled={!this.state.enabled || !!this.state.discoveryUrl}
            value={this.state.userinfoUrl}
            onChange={this.valueChangeHandler}
            type="url"
          />
          <InputField
            name="endSessionUrl"
            label={t("scm-oauth2-plugin.form.endSessionUrl")}
            helpText={t("scm-oauth2-plugin.form.endSessionUrlHelp")}
            disabled={!this.state.enabled || !!this.state.discoveryUrl}
            value={this.state.endSessionUrl}
            onChange={this.valueChangeHandler}
            type="url"
          />
        </div>
        <div>
          <Subtitle subtitle={t("scm-oauth2-plugin.form.client")} />
          <InputField
            name="clientId"
            label={t("scm-oauth2-plugin.form.clientId")}
            helpText={t("scm-oauth2-plugin.form.clientIdHelp")}
            disabled={!this.state.enabled}
            value={this.state.clientId}
            onChange={this.valueChangeHandler}
          />
          <InputField
            name="clientSecret"
            label={t("scm-oauth2-plugin.form.clientSecret")}
            helpText={t("scm-oauth2-plugin.form.clientSecretHelp")}
            placeholder={
              this.state.clientSecretSet
                ? t("scm-oauth2-plugin.form.clientSecretStored")
                : t("scm-oauth2-plugin.form.clientSecretNotStored")
            }
            disabled={!this.state.enabled}
            value={this.state.clientSecret || ""}
            onChange={this.valueChangeHandler}
            type="password"
          />
          <InputField
            name="scopes"
            label={t("scm-oauth2-plugin.form.scopes")}
            helpText={t("scm-oauth2-plugin.form.scopesHelp")}
            disabled={!this.state.enabled}
            value={this.state.scopes}
            onChange={this.valueChangeHandler}
          />
        </div>
        <div>
          <Subtitle subtitle={t("scm-oauth2-plugin.form.attributeMapping")} />
          <InputField
            name="usernameAttribute"
            label={t("scm-oauth2-plugin.form.username")}
            helpText={t("scm-oauth2-plugin.form.usernameHelp")}
            disabled={!this.state.enabled}
            value={this.state.usernameAttribute}
            onChange={this.valueChangeHandler}
          />
          <InputField
            name="displayNameAttribute"
            label={t("scm-oauth2-plugin.form.displayName")}
            helpText={t("scm-oauth2-plugin.form.displayNameHelp")}
            disabled={!this.state.enabled}
            value={this.state.displayNameAttribute}
            onChange={this.valueChangeHandler}
          />
          <InputField
            name="mailAttribute"
            label={t("scm-oauth2-plugin.form.mail")}
            helpText={t("scm-oauth2-plugin.form.mailHelp")}
            disabled={!this.state.enabled}
            value={this.state.mailAttribute}
            onChange={this.valueChangeHandler}
          />
          <InputField
            name="groupAttribute"
            label={t("scm-oauth2-plugin.form.groups")}
            helpText={t("scm-oauth2-plugin.form.groupsHelp")}
            disabled={!this.state.enabled}
            value={this.state.groupAttribute}
            onChange={this.valueChangeHandler}
          />
          <InputField
            name="adminGroup"
            label={t("scm-oauth2-plugin.form.adminGroup")}
            helpText={t("scm-oauth2-plugin.form.adminGroupHelp")}
            disabled={!this.state.enabled}
            value={this.state.adminGroup}
            onChange={this.valueChangeHandler}
          />
          <Checkbox
            name="importRealmRoles"
            label={t("scm-oauth2-plugin.form.importRealmRoles")}
            helpText={t("scm-oauth2-plugin.form.importRealmRolesHelp")}
            checked={this.state.importRealmRoles}
            disabled={!this.state.enabled}
            onChange={this.valueChangeHandler}
          />
          <InputField
            name="realmRolesPath"
            label={t("scm-oauth2-plugin.form.realmRolesPath")}
            helpText={t("scm-oauth2-plugin.form.realmRolesPathHelp")}
            disabled={!this.state.enabled || !this.state.importRealmRoles}
            value={this.state.realmRolesPath}
            onChange={this.valueChangeHandler}
          />
        </div>
      </>
    );
  }

  renderConfigChangedNotification = () => {
    if (this.state.configurationChanged) {
      return (
        <div className="notification is-info">
          <button
            className="delete"
            onClick={() =>
              this.setState({
                ...this.state,
                configurationChanged: false
              })
            }
          />
          {this.props.t("scm-oauth2-plugin.configurationChangedSuccess")}
        </div>
      );
    }
    return null;
  };

  valueChangeHandler = (value: string | boolean, name?: string) => {
    this.setState(
      {
        [name!]: value
      } as Pick<State, keyof State>,
      () =>
        this.props.onConfigurationChange(
          {
            ...this.state
          },
          this.isValid()
        )
    );
  };

  isValid = () => {
    return !this.state.enabled || !!this.state.providerName;
  };
}

export default withTranslation("plugins")(GlobalOAuth2ConfigurationForm);
