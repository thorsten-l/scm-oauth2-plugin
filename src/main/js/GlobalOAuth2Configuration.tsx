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
import { useTranslation } from "react-i18next";
import { Configuration, Title } from "@scm-manager/ui-components";
import GlobalOAuth2ConfigurationForm from "./GlobalOAuth2ConfigurationForm";

type Props = {
  link: string;
};

const GlobalOAuth2Configuration: React.FC<Props> = ({ link }) => {
  const [t] = useTranslation("plugins");

  return (
    <>
      <Title title={t("scm-oauth2-plugin.form.header")} />
      <Configuration link={link} render={(props) => <GlobalOAuth2ConfigurationForm {...props} />} />
    </>
  );
};

export default GlobalOAuth2Configuration;
