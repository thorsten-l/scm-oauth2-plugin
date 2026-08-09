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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import sonia.scm.util.ValidationUtil;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class GroupNameSanitizerTest {

  @ParameterizedTest
  @CsvSource(value = {
    "/developers            | _developers",
    "some/group             | some_group",
    "a:b                    | a_b",
    "a?b                    | a_b",
    "a#b                    | a_b",
    "a;b                    | a_b",
    "a&b                    | a_b",
    "a=b                    | a_b",
    "a%b                    | a_b",
    "a\\b                   | a_b",
    "/a/b/c                 | _a_b_c",
    "@admins                | _admins",
    "developers             | developers",
    "PWA User Managers      | PWA User Managers",
    "USER-OSTFALIA.DE       | USER-OSTFALIA.DE",
    "Ostfalia_soniaInstitute_RZ | Ostfalia_soniaInstitute_RZ"
  }, delimiter = '|')
  void shouldReplaceInvalidCharacters(String input, String expected) {
    assertThat(GroupNameSanitizer.sanitize(input.trim())).isEqualTo(expected.trim());
  }

  @Test
  void shouldReplaceLeadingAndTrailingWhitespace() {
    assertThat(GroupNameSanitizer.sanitize(" dev")).isEqualTo("_dev");
    assertThat(GroupNameSanitizer.sanitize("dev ")).isEqualTo("dev_");
    assertThat(GroupNameSanitizer.sanitize(" dev ")).isEqualTo("_dev_");
  }

  @Test
  void shouldKeepInternalWhitespace() {
    assertThat(GroupNameSanitizer.sanitize("SCM RZ-intern")).isEqualTo("SCM RZ-intern");
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "/developers", "a:b", "@admins", " dev ", "a%b", "x\\y", "///", "  ", "@", "/",
    "PWA User Managers", "USER-OSTFALIA.DE", "SCM RZ-intern", "default-roles-sonia"
  })
  void shouldAlwaysProduceNamesAcceptedByScm(String input) {
    String sanitized = GroupNameSanitizer.sanitize(input);

    assertThat(ValidationUtil.isNameValid(sanitized))
      .withFailMessage("'%s' -> '%s' is not a valid scm name", input, sanitized)
      .isTrue();
  }

  @Test
  void shouldSanitizeWholeSet() {
    Set<String> result = GroupNameSanitizer.sanitize(Set.of("/developers", "admins", "a:b"));

    assertThat(result).containsExactlyInAnyOrder("_developers", "admins", "a_b");
  }

  @Test
  void shouldCollapseNamesWhichBecomeEqual() {
    // both map to the same scm group, which is intentional
    Set<String> result = GroupNameSanitizer.sanitize(Set.of("a/b", "a:b"));

    assertThat(result).containsExactly("a_b");
  }

  @Test
  void shouldHandleEmptyAndNullValues() {
    assertThat(GroupNameSanitizer.sanitize((String) null)).isNull();
    assertThat(GroupNameSanitizer.sanitize("")).isEmpty();
    assertThat(GroupNameSanitizer.sanitize(Set.of())).isEmpty();
  }
}
