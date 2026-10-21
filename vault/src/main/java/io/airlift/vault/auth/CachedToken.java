/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.airlift.vault.auth;

import io.airlift.vault.model.VaultToken;

import static java.lang.Math.max;
import static java.util.Objects.requireNonNull;

/**
 * A token {@link LoginVaultTokenSupplier} holds, together with the two moments that decide what to
 * do with it. The times are readings of a ticker, not wall clock time, so a change of the system
 * clock cannot make a token look expired.
 *
 * @param refreshAtNanos when we should ask for a longer life, two thirds of the lifetime
 * @param expirationNanos when the server stops accepting the token
 * @param neverExpires the server reported no lifetime, so we use the token until the catalog stops.
 *         A root token looks like this
 */
record CachedToken(VaultToken token, long refreshAtNanos, long expirationNanos, boolean neverExpires)
{
    CachedToken(VaultToken token, long refreshAtNanos, long expirationNanos, boolean neverExpires)
    {
        this.token = requireNonNull(token, "token is null");
        this.refreshAtNanos = refreshAtNanos;
        this.expirationNanos = expirationNanos;
        this.neverExpires = neverExpires;
    }

    public boolean needsRefresh(long nowNanos)
    {
        return !neverExpires && nowNanos - refreshAtNanos >= 0;
    }

    public boolean isExpired(long nowNanos)
    {
        return !neverExpires && nowNanos - expirationNanos >= 0;
    }

    public long remainingNanos(long nowNanos)
    {
        return neverExpires ? Long.MAX_VALUE : max(expirationNanos - nowNanos, 0);
    }
}
