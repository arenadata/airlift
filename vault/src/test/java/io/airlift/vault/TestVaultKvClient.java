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

import io.airlift.http.client.HeaderName;
import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.Request;
import io.airlift.http.client.Response;
import io.airlift.http.client.testing.TestingHttpClient;
import io.airlift.http.client.testing.TestingResponse;
import io.airlift.vault.auth.StaticVaultTokenSupplier;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.config.VaultKvConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.model.VaultSecret;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.net.MediaType.JSON_UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TestVaultKvClient
{
    @Test
    void testV1NestedMountAndNamespace()
    {
        List<Request> requests = new ArrayList<>();
        VaultKvClient client = client(new VaultKvConfig().setMount("team/secrets").setVersion(1), request -> {
            requests.add(request);
            return ok("{\"data\":{\"password\":\"sensitive-value\",\"empty\":\"\",\"number\":123,\"nullable\":null}}");
        });
        VaultSecret secret = client.readSecret("service/database");
        assertThat(secret.values()).containsEntry("password", "sensitive-value");
        assertThat(secret.toString()).doesNotContain("password", "sensitive-value");
        assertThat(client.readSecretValue("service/database", "empty")).isEmpty();
        assertThatThrownBy(() -> client.readSecretValue("service/database", "number")).isInstanceOf(VaultException.class);
        assertThatThrownBy(() -> client.readSecretValue("service/database", "missing")).isInstanceOf(VaultException.class);
        assertThat(requests.getFirst().getUri().getPath()).isEqualTo("/v1/team/secrets/service/database");
        assertThat(requests.getFirst().getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo("test-token");
        assertThat(requests.getFirst().getHeader(HeaderName.of("X-Vault-Namespace"))).isEqualTo("team");
    }

    @Test
    void testV2AndNoCaching()
    {
        AtomicInteger reads = new AtomicInteger();
        VaultKvClient client = client(new VaultKvConfig(), request -> {
            assertThat(request.getUri().getPath()).isEqualTo("/v1/secret/data/service");
            return ok("{\"data\":{\"data\":{\"key\":\"value-" + reads.incrementAndGet() + "\"},\"metadata\":{\"destroyed\":false,\"deletion_time\":\"\"}}}");
        });
        assertThat(client.readSecretValue("service", "key")).isEqualTo("value-1");
        assertThat(client.readSecretValue("service", "key")).isEqualTo("value-2");
    }

    @Test
    void testMalformedDeletedAndNonStringResponses()
    {
        for (String body : List.of(
                "null",
                "{}",
                "{\"data\":{}}",
                "{\"data\":{\"data\":null}}",
                "{\"data\":{\"data\":{\"key\":123}}}",
                "{\"data\":{\"data\":{\"key\":\"secret\"},\"metadata\":{\"destroyed\":true}}}",
                "{\"data\":{\"data\":{\"key\":\"secret\"},\"metadata\":{\"deletion_time\":\"2026-10-19\"}}}")) {
            VaultKvClient client = client(new VaultKvConfig(), _ -> ok(body));
            assertThatThrownBy(() -> client.readSecretValue("service", "key"))
                    .isInstanceOf(VaultException.class)
                    .hasMessageNotContaining(body);
        }
    }

    @Test
    void testNoRequestForInvalidPaths()
    {
        VaultKvClient client = client(new VaultKvConfig(), _ -> { throw new AssertionError("No request expected"); });
        for (String path : List.of("", "/root", "end/", "a//b", "a/../b", ".")) {
            assertThatThrownBy(() -> client.readSecret(path)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    private static VaultKvClient client(VaultKvConfig config, TestingHttpClient.Processor processor)
    {
        VaultHttp http = new VaultHttp(new TestingHttpClient(processor), new VaultConnectionConfig()
                .setEndpoint(URI.create("http://vault.invalid:8200"))
                .setNamespace("team"), Duration.ZERO);
        return new VaultKvClient(new VaultSession(http, new StaticVaultTokenSupplier("test-token")), config);
    }

    private static Response ok(String body)
    {
        return TestingResponse.mockResponse(HttpStatus.OK, JSON_UTF_8, body);
    }
}
