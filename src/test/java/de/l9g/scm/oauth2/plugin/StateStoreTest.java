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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the properties the state store has to guarantee: a state can be consumed only
 * once, an unknown or expired state yields nothing, states are unique and every
 * authorization request gets its own pkce verifier.
 */
class StateStoreTest {

  private final StateStore stateStore = new StateStore();

  @Test
  void shouldConsumeStateOnlyOnce() {
    AuthorizationRequest request = stateStore.create("/repos");

    assertThat(stateStore.consume(request.getState())).map(AuthorizationRequest::getRedirectUrl).contains("/repos");
    assertThat(stateStore.consume(request.getState())).isEmpty();
  }

  @Test
  void shouldCreateAPkceVerifierPerRequest() {
    AuthorizationRequest first = stateStore.create("/");
    AuthorizationRequest second = stateStore.create("/");

    assertThat(first.getCodeVerifier()).isNotBlank().isNotEqualTo(second.getCodeVerifier());
  }

  @Test
  void shouldNotConsumeUnknownState() {
    assertThat(stateStore.consume("unknown")).isEmpty();
    assertThat(stateStore.consume(null)).isEmpty();
  }

  @Test
  void shouldCreateUniqueStates() {
    AuthorizationRequest first = stateStore.create("/");
    AuthorizationRequest second = stateStore.create("/");

    assertThat(first.getState()).isNotEqualTo(second.getState());
  }

  @Test
  void shouldNotConsumeExpiredState() {
    MutableClock clock = new MutableClock(Instant.now());
    StateStore store = new StateStore(clock);

    AuthorizationRequest request = store.create("/repos");
    clock.advance(Duration.ofMinutes(11));

    Optional<AuthorizationRequest> consumed = store.consume(request.getState());

    assertThat(consumed).isEmpty();
  }

  private static class MutableClock extends Clock {

    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    private void advance(Duration duration) {
      instant = instant.plus(duration);
    }

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
