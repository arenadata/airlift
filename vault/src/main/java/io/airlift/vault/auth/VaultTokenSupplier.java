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

import io.airlift.vault.VaultSession;

import java.util.Optional;

/**
 * Gives us the token for the {@code X-Vault-Token} header. An implementation either holds a token
 * from the configuration or logs in to get one, and {@link VaultSession} does not see the difference.
 */
public interface VaultTokenSupplier
        extends AutoCloseable
{
    @Override
    default void close() {}

    /**
     * The token to put into the header. An implementation that logs in does it here when it has no
     * token yet or when the one it has is about to expire, so this call can go to the server.
     */
    String get();

    /**
     * Gives the token to repeat a rejected request with, and drops the rejected one from wherever it
     * was kept. The token is returned here and not left for the next {@link #get()}: a supplier that
     * reads a file would otherwise read it twice, and a file that disappears in between would hide
     * the rejection.
     *
     * @return empty when we have no other token, or when the server rejected a token it still
     *         knows. The policy is wrong then, and another token would carry the same policy
     */
    default Optional<String> tokenAfterRejection(String rejectedToken)
    {
        return Optional.empty();
    }
}
