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
 * The {@code data} object of {@link VaultStaticCredentialsResponse}. It holds an account of the
 * database and the password the server rotates for it.
 *
 * @param ttl seconds until the next rotation, for example {@code 28.999998}. It is boxed because a
 *         missing field and a zero mean different things
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record StaticCredentialsData(
        @JsonProperty("username") String username,
        @JsonProperty("password") String password,
        @JsonProperty("ttl") Double ttl)
{
    @Override
    public String toString()
    {
        // the generated toString would print the password
        return format("StaticCredentialsData{username=%s, ttl=%s}", username, ttl);
    }
}
