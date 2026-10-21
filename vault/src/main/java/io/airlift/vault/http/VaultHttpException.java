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
package io.airlift.vault.http;

import io.airlift.vault.VaultException;

import java.util.OptionalInt;

/**
 * A failed exchange, retaining its response status without exposing its body.
 */
public final class VaultHttpException
        extends VaultException
{
    private final int statusCode;

    public VaultHttpException(Category category, int statusCode, String message)
    {
        this(category, statusCode, message, null);
    }

    public VaultHttpException(Category category, int statusCode, String message, Throwable cause)
    {
        super(category, statusCode == 0 ? OptionalInt.empty() : OptionalInt.of(statusCode), message, cause);
        this.statusCode = statusCode;
    }

    /**
     * Zero means no HTTP response was received.
     */
    public int statusCode()
    {
        return statusCode;
    }
}
