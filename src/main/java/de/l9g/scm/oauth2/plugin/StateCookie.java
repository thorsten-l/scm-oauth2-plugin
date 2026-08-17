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
 *
 * <p>The methods return a ready made {@code Set-Cookie} header value instead of a
 * {@code Cookie} object, because the servlet cookie api of this version cannot
 * express {@code SameSite}.
 */
final class StateCookie {

  static final String NAME = "X-SCM-OAuth2-State";

  /** Same lifetime as the state in the {@link StateStore}. */
  private static final int MAX_AGE_IN_SECONDS = 600;

  private StateCookie() {
  }

  /**
   * @return header value which stores the state in the browser
   */
  static String create(HttpServletRequest request, String state) {
    return header(request, state, MAX_AGE_IN_SECONDS);
  }

  /**
   * @return header value which deletes the cookie, sent with the answer of the
   *         callback so a used state does not stay in the browser
   */
  static String invalidate(HttpServletRequest request) {
    return header(request, "", 0);
  }

  /**
   * @return state stored in the browser, empty if there is no such cookie
   */
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

    // only over https, otherwise the cookie would be dropped by the browser on a
    // plain http development instance
    if (request.isSecure()) {
      cookie.append("; Secure");
    }

    return cookie.toString();
  }

  /**
   * The cookie is scoped to the context path of SCM-Manager, so it is not sent to
   * other applications on the same host.
   */
  private static String path(HttpServletRequest request) {
    String contextPath = request.getContextPath();
    return Strings.isNullOrEmpty(contextPath) ? "/" : contextPath;
  }
}
