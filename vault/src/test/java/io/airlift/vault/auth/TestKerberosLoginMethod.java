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

import com.google.common.net.MediaType;
import io.airlift.http.client.HeaderName;
import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.Request;
import io.airlift.http.client.StaticBodyGenerator;
import io.airlift.http.client.testing.TestingHttpClient;
import io.airlift.http.client.testing.TestingResponse;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.http.VaultHttpException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static io.airlift.vault.enums.VaultAuthMethod.KERBEROS;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TestKerberosLoginMethod
{
    private static final String LOGIN = "{\"auth\":{\"client_token\":\"test-issued-token\",\"lease_duration\":60,\"renewable\":true}}";
    @TempDir
    Path directory;

    @Test
    void testFreshNegotiateOnEachAllowedRetryAndTokenLifecycle()
            throws Exception
    {
        List<Request> requests = new ArrayList<>();
        AtomicInteger generated = new AtomicInteger();
        VaultConnectionConfig config = config();
        TestingHttpClient client = new TestingHttpClient(request -> {
            requests.add(request);
            if (requests.size() == 1) {
                return response(503, "private server failure");
            }
            if (requests.size() == 2) {
                throw new ConnectException("private transport failure");
            }
            return response(200, LOGIN);
        });
        VaultHttp http = new VaultHttp(client, config, Duration.ZERO);
        try (LoginVaultTokenSupplier supplier = new LoginVaultTokenSupplier(new KerberosLoginMethod(http, config, () -> "fresh-" + generated.incrementAndGet()), http)) {
            assertThat(supplier.get()).isEqualTo("test-issued-token");
            assertThat(supplier.get()).isEqualTo("test-issued-token");
            assertThat(generated.get()).isEqualTo(3);
            for (int i = 0; i < requests.size(); i++) {
                Request request = requests.get(i);
                assertThat(request.getUri()).isEqualTo(URI.create("https://bao.example:8200/v1/auth/kerberos-trino/login"));
                assertThat(request.getMethod()).isEqualTo("POST");
                assertThat(request.getHeader(HeaderName.of("Authorization"))).isEqualTo("Negotiate fresh-" + (i + 1));
                assertThat(request.getHeader(HeaderName.of("X-Vault-Token"))).isNull();
                assertThat(request.getHeader(HeaderName.of("X-Vault-Namespace"))).isEqualTo("team");
                assertThat(request.isFollowRedirects()).isFalse();
                assertThat(new String(((StaticBodyGenerator) request.getBodyGenerator()).getBody(), UTF_8)).contains("\"role\" : \"trino-config\"");
            }
        }
        Request revoke = requests.getLast();
        assertThat(revoke.getUri().getPath()).isEqualTo("/v1/auth/token/revoke-self");
        assertThat(revoke.getHeader(HeaderName.of("Authorization"))).isNull();
        assertThat(revoke.getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo("test-issued-token");
        assertThat(generated.get()).isEqualTo(3);
    }

    @Test
    void testAmbiguousErrorsAndRedirectsNeverRepeatLogin()
            throws Exception
    {
        for (int status : new int[] {301, 302, 307, 308, 401, 403, 500, 502}) {
            AtomicInteger generated = new AtomicInteger();
            VaultHttp http = new VaultHttp(new TestingHttpClient(_ -> response(status, "secret-APREQ-response")), config(), Duration.ZERO);
            assertThatThrownBy(() -> new KerberosLoginMethod(http, config(), () -> "secret-APREQ-" + generated.incrementAndGet()).login())
                    .isInstanceOf(VaultHttpException.class).hasMessageContaining("HTTP " + status)
                    .hasMessageNotContaining("secret-APREQ").hasNoCause();
            assertThat(generated.get()).as("status %s", status).isEqualTo(1);
        }
        AtomicInteger generated = new AtomicInteger();
        VaultHttp http = new VaultHttp(new TestingHttpClient(_ -> { throw new SocketTimeoutException("secret-APREQ"); }), config(), Duration.ZERO);
        assertThatThrownBy(() -> new KerberosLoginMethod(http, config(), () -> "fresh-" + generated.incrementAndGet()).login())
                .isInstanceOf(VaultHttpException.class).hasNoCause().hasMessageNotContaining("secret-APREQ");
        assertThat(generated.get()).isEqualTo(1);
    }

    @Test
    void testGenerationAndJsonFailuresAreSanitized()
            throws Exception
    {
        VaultHttp noRequest = new VaultHttp(new TestingHttpClient(_ -> { throw new AssertionError("No request expected"); }), config(), Duration.ZERO);
        assertThatThrownBy(() -> new KerberosLoginMethod(noRequest, config(), () -> { throw new IllegalStateException("private-key-material"); }).login())
                .isInstanceOf(VaultHttpException.class).hasNoCause().hasMessageNotContaining("private-key-material");
        VaultHttp badJson = new VaultHttp(new TestingHttpClient(_ -> response(200, "private-response-content")), config(), Duration.ZERO);
        assertThatThrownBy(() -> new KerberosLoginMethod(badJson, config(), () -> "private-APREQ").login())
                .isInstanceOf(VaultHttpException.class).hasNoCause().hasMessageNotContaining("private-response-content");
    }

    private VaultConnectionConfig config()
            throws Exception
    {
        Path keytab = directory.resolve("client.keytab");
        if (!Files.exists(keytab)) {
            Files.createFile(keytab);
        }
        return new VaultConnectionConfig().setEndpoint(URI.create("https://bao.example:8200"))
                .setAuthMethod(KERBEROS).setKerberosMount("kerberos-trino").setKerberosRole("trino-config")
                .setKerberosPrincipal("trino/node.example@EXAMPLE.COM").setKerberosKeytab(keytab.toFile())
                .setKerberosServicePrincipal("HTTP/bao.example@EXAMPLE.COM").setNamespace("team");
    }

    private static TestingResponse response(int status, String body)
    {
        return new TestingResponse(HttpStatus.OK, TestingResponse.contentType(MediaType.JSON_UTF_8), body.getBytes(UTF_8))
        {
            @Override
            public int getStatusCode()
            {
                return status;
            }
        };
    }
}
