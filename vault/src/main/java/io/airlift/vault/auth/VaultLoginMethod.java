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

import io.airlift.vault.VaultException;
import io.airlift.vault.http.VaultHttpException;
import io.airlift.vault.model.VaultToken;
import io.airlift.vault.response.VaultLoginResponse;
import io.airlift.vault.response.VaultLoginResponse.Auth;

import java.time.Duration;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.lang.Math.max;
import static java.lang.String.format;

/**
 * One request to an auth mount.
 */
public interface VaultLoginMethod
{
    /**
     * Logs in and returns a new token. It never returns a token it kept, that is the work of
     * {@link LoginVaultTokenSupplier}.
     */
    VaultToken login();

    /**
     * A short text for error messages, for example {@code "the AppRole method on mount 'approle'"}.
     */
    String description();

    /**
     * Takes the token out of a login or a renewal response. The lifetime and the renewable flag
     * come from {@code auth}. At the top level a login always reports {@code 0} and {@code false}.
     */
    static VaultToken issuedToken(VaultLoginResponse response, String operation)
    {
        Auth auth = response == null ? null : response.auth();
        if (auth == null || isNullOrEmpty(auth.clientToken())) {
            throw new VaultHttpException(VaultException.Category.REFUSED, 200, format("%s: response has no 'auth.client_token'", operation));
        }
        return new VaultToken(auth.clientToken(), Duration.ofSeconds(max(auth.leaseDuration(), 0)), auth.renewable());
    }
}
