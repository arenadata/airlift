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

/**
 * Response of {@code GET /v1/<mount>/creds/<role>}. This is the request that makes the server
 * create an account in the database.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record VaultDynamicCredentialsResponse(
        @JsonProperty("lease_id") String leaseId,
        @JsonProperty("lease_duration") long leaseDuration,
        @JsonProperty("renewable") boolean renewable,
        @JsonProperty("data") DynamicCredentialsData data) {}
