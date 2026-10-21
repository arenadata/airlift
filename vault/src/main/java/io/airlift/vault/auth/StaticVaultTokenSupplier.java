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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;

/**
 * The token from {@code vault.token}, used as it is. We have no way to get another one, so a
 * rejected token stays rejected and the request is not repeated.
 */
public class StaticVaultTokenSupplier
        implements VaultTokenSupplier
{
    private final String token;

    public StaticVaultTokenSupplier(String token)
    {
        checkArgument(!isNullOrEmpty(token), "token is null or empty");
        this.token = token;
    }

    @Override
    public String get()
    {
        return token;
    }
}
