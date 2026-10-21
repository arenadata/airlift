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
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

/**
 * Credentials of a database account, as the database secrets engine gives them to us.
 *
 * @param ttl how long we may use them. {@link Duration#ZERO} means the server told us nothing
 * @param leaseId the lease these credentials hang on. A static role has none, it is not leased
 */
public record VaultCredentials(
        String username,
        String password,
        Duration ttl,
        Optional<String> leaseId,
        boolean renewable)
{
    public VaultCredentials(String username, String password, Duration ttl, Optional<String> leaseId, boolean renewable)
    {
        checkArgument(!isNullOrEmpty(username), "username is null or empty");
        checkArgument(!isNullOrEmpty(password), "password is null or empty");
        requireNonNull(ttl, "ttl is null");
        checkArgument(!ttl.isNegative(), "ttl is negative");
        requireNonNull(leaseId, "leaseId is null");
        this.username = username;
        this.password = password;
        this.ttl = ttl;
        this.leaseId = leaseId;
        this.renewable = renewable;
    }

    @Override
    public String toString()
    {
        // the generated toString would print the password
        return format("VaultCredentials{username=%s, ttl=%s, leaseId=%s, renewable=%s}", username, ttl, leaseId, renewable);
    }
}
