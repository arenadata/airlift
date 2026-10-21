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

import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;

/**
 * KV data. Its string representation never includes keys or values.
 */
public record VaultSecret(Map<String, Object> values)
{
    public VaultSecret
    {
        values = unmodifiableMap(new LinkedHashMap<>(requireNonNull(values, "values is null")));
    }

    @Override
    public String toString()
    {
        return "VaultSecret{[redacted]}";
    }
}
