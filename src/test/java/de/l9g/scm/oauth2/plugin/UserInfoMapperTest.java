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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.authc.AuthenticationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.user.User;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class UserInfoMapperTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Mock
  private OAuth2Context context;

  private UserInfoMapper mapper;

  @BeforeEach
  void setUpMapper() {
    lenient().when(context.get()).thenReturn(new OAuth2Configuration());
    mapper = new UserInfoMapper(context);
  }

  @Test
  void shouldCreateUserFromUserInfo() throws Exception {
    JsonNode userInfo = objectMapper.readTree(
      "{\"sub\":\"4711\",\"preferred_username\":\"trillian\",\"name\":\"Tricia McMillan\",\"email\":\"trillian@hitchhiker.com\"}"
    );

    User user = mapper.createUser(userInfo);

    assertThat(user.getName()).isEqualTo("trillian");
    assertThat(user.getDisplayName()).isEqualTo("Tricia McMillan");
    assertThat(user.getMail()).isEqualTo("trillian@hitchhiker.com");
    assertThat(user.isExternal()).isTrue();
  }

  @Test
  void shouldFallBackToSubClaimAsUsername() throws Exception {
    JsonNode userInfo = objectMapper.readTree("{\"sub\":\"4711\"}");

    User user = mapper.createUser(userInfo);

    assertThat(user.getName()).isEqualTo("4711");
    // the display name is left empty on purpose, so that a stored one survives
    assertThat(user.getDisplayName()).isNull();
  }

  @Test
  void shouldLeaveInvalidMailBlank() throws Exception {
    JsonNode userInfo = objectMapper.readTree(
      "{\"preferred_username\":\"trillian\",\"email\":\"not-a-mail-address\"}"
    );

    User user = mapper.createUser(userInfo);

    assertThat(user.getMail()).isNull();
  }

  @Test
  void shouldFailWithoutUsernameAndSub() throws Exception {
    JsonNode userInfo = objectMapper.readTree("{\"name\":\"Tricia McMillan\"}");

    assertThatThrownBy(() -> mapper.createUser(userInfo)).isInstanceOf(AuthenticationException.class);
  }

  @Test
  void shouldCreateGroupsFromArrayClaim() throws Exception {
    JsonNode userInfo = objectMapper.readTree("{\"groups\":[\"heartOfGold\",\"restaurantAtTheEndOfTheUniverse\"]}");

    Set<String> groups = mapper.createGroups(userInfo);

    assertThat(groups).containsExactlyInAnyOrder("heartOfGold", "restaurantAtTheEndOfTheUniverse");
  }

  @Test
  void shouldCreateGroupsFromSingleValueClaim() throws Exception {
    JsonNode userInfo = objectMapper.readTree("{\"groups\":\"heartOfGold\"}");

    Set<String> groups = mapper.createGroups(userInfo);

    assertThat(groups).containsExactly("heartOfGold");
  }

  @Test
  void shouldReturnEmptyGroupsWithoutClaim() throws Exception {
    JsonNode userInfo = objectMapper.readTree("{\"preferred_username\":\"trillian\"}");

    Set<String> groups = mapper.createGroups(userInfo);

    assertThat(groups).isEmpty();
  }
}
