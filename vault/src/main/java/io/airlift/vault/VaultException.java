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

import static java.util.Objects.requireNonNull;

/**
 * A failure whose classification is independent of the application using Vault.
 */
public class VaultException
        extends RuntimeException
{
    public enum Category
    {
        UNAVAILABLE,
        REFUSED,
    }

    private final Category category;
    private final OptionalInt httpStatusCode;

    public VaultException(Category category, String message)
    {
        this(category, OptionalInt.empty(), message, null);
    }

    public VaultException(Category category, String message, Throwable cause)
    {
        this(category, OptionalInt.empty(), message, cause);
    }

    protected VaultException(Category category, OptionalInt httpStatusCode, String message, Throwable cause)
    {
        super(message, cause);
        this.category = requireNonNull(category, "category is null");
        this.httpStatusCode = requireNonNull(httpStatusCode, "httpStatusCode is null");
    }

    public Category category()
    {
        return category;
    }

    public OptionalInt httpStatusCode()
    {
        return httpStatusCode;
    }
}
