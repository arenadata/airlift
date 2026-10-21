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
package io.airlift.vault.model;

import java.time.Duration;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

/**
 * A token that an auth mount gives us.
 *
 * @param ttl how long the token still lives. {@link Duration#ZERO} means it never expires, a root
 *         token is like this
 * @param renewable true if we can call {@code auth/token/renew-self}. A batch token cannot be
 *         renewed, so it is false
 */
public record VaultToken(String clientToken, Duration ttl, boolean renewable)
{
    public VaultToken(String clientToken, Duration ttl, boolean renewable)
    {
        checkArgument(!isNullOrEmpty(clientToken), "clientToken is null or empty");
        requireNonNull(ttl, "ttl is null");
        checkArgument(!ttl.isNegative(), "ttl is negative");
        this.clientToken = clientToken;
        this.ttl = ttl;
        this.renewable = renewable;
    }

    @Override
    public String toString()
    {
        // the generated implementation would leak the token
        return format("VaultToken{ttl=%s, renewable=%s}", ttl, renewable);
    }
}
