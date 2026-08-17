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

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * The public keys of a json web key set (rfc 7517), reduced to what is needed to
 * verify a signature: the key itself, its id and the algorithm family it belongs
 * to.
 *
 * <p>Immutable, produced by {@link JwksClient} and cached by
 * {@link JwksProvider}.
 */
final class JsonWebKeys {

  private final List<Entry> entries;

  private JsonWebKeys(List<Entry> entries) {
    this.entries = Collections.unmodifiableList(entries);
  }

  static JsonWebKeys of(List<Entry> entries) {
    return new JsonWebKeys(new ArrayList<>(entries));
  }

  static JsonWebKeys empty() {
    return new JsonWebKeys(Collections.emptyList());
  }

  boolean isEmpty() {
    return entries.isEmpty();
  }

  /**
   * Looks up the key for a signature.
   *
   * <p>If the token names a key id, only that key is accepted — trying other keys
   * would defeat the purpose of the identifier. Tokens without a key id are matched
   * by key type, which is unambiguous as long as the provider publishes one key per
   * type.
   *
   * @param keyId         value of the {@code kid} header, may be {@code null}
   * @param keyType       required key type, {@code RSA} or {@code EC}
   * @return the matching key, empty if the set does not contain one
   */
  Optional<PublicKey> find(String keyId, String keyType) {
    for (Entry entry : entries) {
      if (!entry.keyType.equals(keyType)) {
        continue;
      }
      if (Strings.isNullOrEmpty(keyId)) {
        return Optional.of(entry.key);
      }
      if (keyId.equals(entry.keyId)) {
        return Optional.of(entry.key);
      }
    }
    return Optional.empty();
  }

  /**
   * A single usable key of the set.
   */
  static final class Entry {

    private final String keyId;
    private final String keyType;
    private final PublicKey key;

    Entry(String keyId, String keyType, PublicKey key) {
      this.keyId = keyId;
      this.keyType = keyType;
      this.key = key;
    }
  }
}
