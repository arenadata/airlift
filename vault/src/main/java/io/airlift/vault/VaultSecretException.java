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
package io.airlift.vault;

import java.util.OptionalInt;

import static io.airlift.vault.VaultException.Category.REFUSED;
import static java.util.Objects.requireNonNull;

/**
 * A safe, structured failure to extract a KV value from a successful HTTP response.
 */
public final class VaultSecretException
        extends VaultException
{
    public enum Reason
    {
        MISSING_OR_NON_STRING_FIELD,
        INVALID_RESPONSE,
        DELETED_OR_DESTROYED,
    }

    private final Reason reason;

    public VaultSecretException(Reason reason)
    {
        super(REFUSED, OptionalInt.of(200), message(requireNonNull(reason, "reason is null")), null);
        this.reason = reason;
    }

    public Reason reason()
    {
        return reason;
    }

    private static String message(Reason reason)
    {
        return switch (reason) {
            case MISSING_OR_NON_STRING_FIELD -> "Vault KV secret field is missing or is not a string";
            case INVALID_RESPONSE -> "Vault KV response is malformed";
            case DELETED_OR_DESTROYED -> "Vault KV secret version was deleted or destroyed";
        };
    }
}
