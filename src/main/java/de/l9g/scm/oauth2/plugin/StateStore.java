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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Singleton;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * Holds the pending authorization requests. The state protects the callback
 * endpoint against csrf and is additionally bound to the browser which started
 * the flow, see {@link StateCookie}. Each state can be consumed only once.
 */
@Singleton
public class StateStore {

  private static final Logger LOG = LoggerFactory.getLogger(StateStore.class);

  private static final long EXPIRATION_IN_MILLIS = 10L * 60L * 1000L;
  private static final int STATE_LENGTH_IN_BYTES = 24;

  /**
   * The login endpoint can be called anonymously, so the number of pending
   * requests has to be limited to keep an attacker from exhausting the memory.
   */
  static final int MAX_PENDING_REQUESTS = 10_000;

  private final SecureRandom random = new SecureRandom();
  private final ConcurrentMap<String, Entry> states = new ConcurrentHashMap<>();
  private final Clock clock;

  public StateStore() {
    this(Clock.systemUTC());
  }

  StateStore(Clock clock) {
    this.clock = clock;
  }

  public AuthorizationRequest create(String redirectUrl) {
    removeExpiredStates();
    enforceSizeLimit();

    byte[] bytes = new byte[STATE_LENGTH_IN_BYTES];
    random.nextBytes(bytes);
    String state = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

    AuthorizationRequest request = new AuthorizationRequest(state, Pkce.createVerifier(), redirectUrl);
    states.put(state, new Entry(request, clock.millis()));
    return request;
  }

  public Optional<AuthorizationRequest> consume(String state) {
    if (state == null) {
      return Optional.empty();
    }
    Entry entry = states.remove(state);
    if (entry == null || isExpired(entry)) {
      return Optional.empty();
    }
    return Optional.of(entry.request);
  }

  int size() {
    return states.size();
  }

  private void removeExpiredStates() {
    states.entrySet().removeIf(entry -> isExpired(entry.getValue()));
  }

  private void enforceSizeLimit() {
    int excess = states.size() - (MAX_PENDING_REQUESTS - 1);
    if (excess <= 0) {
      return;
    }
    LOG.warn("more than {} pending authorization requests, dropping the oldest ones", MAX_PENDING_REQUESTS);
    List<String> oldest = states.entrySet().stream()
      .sorted(Comparator.comparingLong(entry -> entry.getValue().createdAt))
      .limit(excess)
      .map(Map.Entry::getKey)
      .collect(Collectors.toList());
    oldest.forEach(states::remove);
  }

  private boolean isExpired(Entry entry) {
    return clock.millis() - entry.createdAt > EXPIRATION_IN_MILLIS;
  }

  private static class Entry {
    private final AuthorizationRequest request;
    private final long createdAt;

    private Entry(AuthorizationRequest request, long createdAt) {
      this.request = request;
      this.createdAt = createdAt;
    }
  }
}
