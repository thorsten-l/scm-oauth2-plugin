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

import de.l9g.scm.oauth2.plugin.OAuth2Configuration;
import de.l9g.scm.oauth2.plugin.OAuth2Context;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.ws.rs.core.Response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
/**
 * Tests the special rules of the configuration endpoint: the stored client secret is
 * never returned, an empty secret on update keeps it while a submitted one replaces
 * it, endpoint urls have to be absolute http urls, and an enabled configuration
 * without a provider name is rejected.
 *
 * <p>The resource checks shiro permissions, therefore a subject is bound to the
 * thread context in the setup and unbound afterwards.
 */
class ConfigurationResourceTest {

  private static final String STORED_SECRET = "the-stored-secret";

  @Mock
  private OAuth2Context context;

  @Mock
  private ConfigurationMapper mapper;

  @Mock
  private Subject subject;

  private ConfigurationResource resource;

  private final OAuth2Configuration stored = new OAuth2Configuration();

  @BeforeEach
  void setUpResource() {
    resource = new ConfigurationResource(context, mapper);
    stored.setClientSecret(STORED_SECRET);
    stored.setProviderName("Provider");
    lenient().when(context.get()).thenReturn(stored);
    ThreadContext.bind(subject);
  }

  @AfterEach
  void unbindSubject() {
    ThreadContext.unbindSubject();
  }

  @Test
  void shouldNeverReturnTheStoredSecret() {
    ConfigurationDto dto = new ConfigurationDto();
    dto.setClientSecret(STORED_SECRET);
    when(mapper.toDto(stored)).thenReturn(dto);

    ConfigurationDto result = resource.get();

    assertThat(result.getClientSecret()).isNull();
    assertThat(result.isClientSecretSet()).isTrue();
  }

  @Test
  void shouldReportMissingSecret() {
    stored.setClientSecret(null);
    when(mapper.toDto(stored)).thenReturn(new ConfigurationDto());

    assertThat(resource.get().isClientSecretSet()).isFalse();
  }

  @Test
  void shouldKeepStoredSecretIfNoneIsSubmitted() {
    ConfigurationDto dto = validDto();
    dto.setClientSecret("");
    OAuth2Configuration mapped = new OAuth2Configuration();
    mapped.setClientSecret("");
    when(mapper.fromDto(dto)).thenReturn(mapped);

    Response result = resource.update(dto);

    assertThat(result.getStatus()).isEqualTo(204);
    ArgumentCaptor<OAuth2Configuration> captor = ArgumentCaptor.forClass(OAuth2Configuration.class);
    verify(context).set(captor.capture());
    assertThat(captor.getValue().getClientSecret()).isEqualTo(STORED_SECRET);
  }

  @Test
  void shouldReplaceSecretIfSubmitted() {
    ConfigurationDto dto = validDto();
    dto.setClientSecret("a-new-secret");
    OAuth2Configuration mapped = new OAuth2Configuration();
    mapped.setClientSecret("a-new-secret");
    when(mapper.fromDto(dto)).thenReturn(mapped);

    resource.update(dto);

    ArgumentCaptor<OAuth2Configuration> captor = ArgumentCaptor.forClass(OAuth2Configuration.class);
    verify(context).set(captor.capture());
    assertThat(captor.getValue().getClientSecret()).isEqualTo("a-new-secret");
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "file:///etc/passwd",
    "ftp://idp.hitchhiker.com",
    "/relative/path",
    "idp.hitchhiker.com/auth",
    "jar:http://idp.hitchhiker.com!/x",
    "not a url"
  })
  void shouldRejectNonHttpEndpointUrls(String url) {
    ConfigurationDto dto = validDto();
    dto.setTokenUrl(url);

    Response result = resource.update(dto);

    assertThat(result.getStatus()).isEqualTo(400);
    verify(context, never()).set(org.mockito.ArgumentMatchers.any());
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "http://idp.hitchhiker.com/auth",
    "https://idp.hitchhiker.com/realms/main"
  })
  void shouldAcceptHttpEndpointUrls(String url) {
    ConfigurationDto dto = validDto();
    dto.setDiscoveryUrl(url);
    when(mapper.fromDto(dto)).thenReturn(new OAuth2Configuration());

    Response result = resource.update(dto);

    assertThat(result.getStatus()).isEqualTo(204);
  }

  @Test
  void shouldRejectEnabledConfigurationWithoutProviderName() {
    ConfigurationDto dto = validDto();
    dto.setProviderName(null);

    Response result = resource.update(dto);

    assertThat(result.getStatus()).isEqualTo(400);
    verify(context, never()).set(org.mockito.ArgumentMatchers.any());
  }

  private ConfigurationDto validDto() {
    ConfigurationDto dto = new ConfigurationDto();
    dto.setEnabled(true);
    dto.setProviderName("Provider");
    return dto;
  }
}
