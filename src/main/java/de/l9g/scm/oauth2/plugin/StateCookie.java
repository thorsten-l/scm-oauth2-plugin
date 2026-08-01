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

import com.google.common.base.Strings;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Binds the state of a pending authorization request to the browser which
 * started it. Without this binding an attacker could obtain a valid
 * state/code pair and make a victim call the callback with it, which would
 * silently log the victim in as the attacker (login csrf, see rfc 9700 4.7).
 */
final class StateCookie {

  static final String NAME = "X-SCM-OAuth2-State";

  private static final int MAX_AGE_IN_SECONDS = 600;

  private StateCookie() {
  }

  static String create(HttpServletRequest request, String state) {
    return header(request, state, MAX_AGE_IN_SECONDS);
  }

  static String invalidate(HttpServletRequest request) {
    return header(request, "", 0);
  }

  static Optional<String> read(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    for (Cookie cookie : cookies) {
      if (NAME.equals(cookie.getName()) && !Strings.isNullOrEmpty(cookie.getValue())) {
        return Optional.of(cookie.getValue());
      }
    }
    return Optional.empty();
  }

  private static String header(HttpServletRequest request, String value, int maxAge) {
    StringBuilder cookie = new StringBuilder(NAME)
      .append('=').append(value)
      .append("; Path=").append(path(request))
      .append("; Max-Age=").append(maxAge)
      .append("; HttpOnly")
      // the callback is a cross site top level navigation from the identity
      // provider, therefore the cookie must not be restricted to same site
      // requests, but lax is sufficient for a top level GET
      .append("; SameSite=Lax");

    if (request.isSecure()) {
      cookie.append("; Secure");
    }

    return cookie.toString();
  }

  private static String path(HttpServletRequest request) {
    String contextPath = request.getContextPath();
    return Strings.isNullOrEmpty(contextPath) ? "/" : contextPath;
  }
}
