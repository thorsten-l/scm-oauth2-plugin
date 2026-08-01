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

import jakarta.inject.Singleton;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Keeps the id token of the last login per user in memory. It is used as
 * {@code id_token_hint} for the RP-initiated logout at the identity provider.
 * The store is not persisted; after a restart the logout works without hint.
 * Tokens of users who never log out expire after {@value #EXPIRATION_IN_HOURS}
 * hours, so they are not kept forever.
 */
@Singleton
public class IdTokenStore {

  static final long EXPIRATION_IN_HOURS = 12L;

  private static final long EXPIRATION_IN_MILLIS = EXPIRATION_IN_HOURS * 60L * 60L * 1000L;

  private final ConcurrentMap<String, Entry> idTokens = new ConcurrentHashMap<>();
  private final Clock clock;

  public IdTokenStore() {
    this(Clock.systemUTC());
  }

  IdTokenStore(Clock clock) {
    this.clock = clock;
  }

  public void put(String principal, String idToken) {
    removeExpiredTokens();
    if (!Strings.isNullOrEmpty(idToken)) {
      idTokens.put(principal, new Entry(idToken, clock.millis()));
    }
  }

  public Optional<String> remove(String principal) {
    if (principal == null) {
      return Optional.empty();
    }
    Entry entry = idTokens.remove(principal);
    if (entry == null || isExpired(entry)) {
      return Optional.empty();
    }
    return Optional.of(entry.idToken);
  }

  private void removeExpiredTokens() {
    idTokens.entrySet().removeIf(entry -> isExpired(entry.getValue()));
  }

  private boolean isExpired(Entry entry) {
    return clock.millis() - entry.createdAt > EXPIRATION_IN_MILLIS;
  }

  private static class Entry {
    private final String idToken;
    private final long createdAt;

    private Entry(String idToken, long createdAt) {
      this.idToken = idToken;
      this.createdAt = createdAt;
    }
  }
}
