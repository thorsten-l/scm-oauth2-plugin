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

import React, { FC, ReactNode } from "react";
import { Link, Links } from "@scm-manager/ui-types";

type Props = {
  links: Links;
  from: string;
  loginUrl?: string;
  className?: string;
  content?: ReactNode;
};

const OAuth2LoginLink: FC<Props> = ({ links, from, className, content }) => {
  const loginLink = (links?.oauth2Login as Link)?.href;
  const providerName = (links?.oauth2Login as Link)?.name;
  return (
    <a
      href={`${loginLink}?from=${encodeURIComponent(from || "/")}`}
      className={className}
      title={providerName}
    >
      {content}
    </a>
  );
};

export default OAuth2LoginLink;
