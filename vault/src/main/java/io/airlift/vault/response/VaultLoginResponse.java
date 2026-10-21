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
package io.airlift.vault.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import static java.lang.String.format;

/**
 * Response of {@code POST /v1/auth/<mount>/login} and of {@code POST /v1/auth/token/renew-self}.
 * <p>
 * The token is described below {@code auth}. The same fields at the top level are always {@code 0}
 * and {@code false}, so do not read them.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record VaultLoginResponse(@JsonProperty("auth") Auth auth)
{
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Auth(
            @JsonProperty("client_token") String clientToken,
            @JsonProperty("lease_duration") long leaseDuration,
            @JsonProperty("renewable") boolean renewable)
    {
        @Override
        public String toString()
        {
            // the generated toString would print the token itself
            return format("Auth{leaseDuration=%s, renewable=%s}", leaseDuration, renewable);
        }
    }
}
