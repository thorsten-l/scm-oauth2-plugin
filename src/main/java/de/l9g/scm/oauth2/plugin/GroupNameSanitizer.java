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
import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * Maps group names of the identity provider to names which are valid for
 * SCM-Manager. Characters which SCM-Manager does not allow are replaced by an
 * underscore, so that for example a keycloak full group path {@code /developers}
 * becomes the group {@code _developers} instead of being lost.
 *
 * <p>The sanitized name is used everywhere: for the created group, for the
 * membership and for the authorization, so that permissions granted to the
 * group really apply.
 */
final class GroupNameSanitizer {

  private static final Logger LOG = LoggerFactory.getLogger(GroupNameSanitizer.class);

  private static final char REPLACEMENT = '_';

  /**
   * Characters which SCM-Manager does not accept at any position of a name.
   */
  private static final String FORBIDDEN = ":/?#;&=%\\";

  private GroupNameSanitizer() {
  }

  /**
   * Sanitizes a whole set of names. Two names may collapse into one (for example
   * {@code /dev} and {@code :dev}), the set removes the duplicate.
   *
   * @param names names as delivered by the identity provider
   * @return valid names, without empty entries
   */
  static Set<String> sanitize(Set<String> names) {
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();
    for (String name : names) {
      String sanitized = sanitize(name);
      if (!Strings.isNullOrEmpty(sanitized)) {
        builder.add(sanitized);
      }
    }
    return builder.build();
  }

  /**
   * @param name name of the identity provider, may be {@code null}
   * @return name with every invalid character replaced by an underscore; the
   *         length stays the same, nothing is removed
   */
  static String sanitize(String name) {
    if (Strings.isNullOrEmpty(name)) {
      return name;
    }

    char[] characters = name.toCharArray();
    for (int i = 0; i < characters.length; i++) {
      if (isForbiddenAt(characters, i)) {
        characters[i] = REPLACEMENT;
      }
    }

    String sanitized = new String(characters);
    if (!sanitized.equals(name)) {
      LOG.debug("replaced invalid characters in group name '{}', using '{}'", name, sanitized);
    }
    return sanitized;
  }

  /**
   * Mirrors the name validation of the core ({@code ValidationUtil.isNameValid}):
   * some characters are forbidden everywhere, others only at the beginning or at
   * the end of a name.
   */
  private static boolean isForbiddenAt(char[] characters, int index) {
    char character = characters[index];
    if (FORBIDDEN.indexOf(character) >= 0) {
      return true;
    }
    // a name must neither start with whitespace or '@' nor end with whitespace
    if (index == 0) {
      return Character.isWhitespace(character) || character == '@';
    }
    return index == characters.length - 1 && Character.isWhitespace(character);
  }
}
