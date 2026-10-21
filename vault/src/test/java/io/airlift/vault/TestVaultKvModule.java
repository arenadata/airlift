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

import com.google.common.collect.ImmutableMap;
import com.google.inject.BindingAnnotation;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.sun.net.httpserver.HttpServer;
import io.airlift.bootstrap.Bootstrap;
import io.airlift.bootstrap.LifeCycleManager;
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpClientConfig;
import io.airlift.units.Duration;
import io.airlift.vault.config.VaultDatabaseConfig;
import io.airlift.vault.http.ForVault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.google.inject.Scopes.SINGLETON;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TestVaultKvModule
{
    @Test
    void testKerberosRequiresHostnameVerification(@TempDir Path directory)
            throws Exception
    {
        Path keytab = Files.createFile(directory.resolve("client.keytab"));
        assertThatThrownBy(() -> new Bootstrap(new VaultKvModule("vault", First.class))
                .doNotInitializeLogging()
                .quiet()
                .setRequiredConfigurationProperties(ImmutableMap.<String, String>builder()
                        .put("vault.endpoint", "https://bao.example:8200")
                        .put("vault.auth.method", "KERBEROS")
                        .put("vault.auth.kerberos.role", "trino-config")
                        .put("vault.auth.kerberos.principal", "trino/node.example@EXAMPLE.COM")
                        .put("vault.auth.kerberos.keytab", keytab.toString())
                        .put("vault.auth.kerberos.service-principal", "HTTP/bao.example@EXAMPLE.COM")
                        .put("vault.http-client.https.hostname-verification", "false")
                        .buildOrThrow())
                .initialize())
                .hasStackTraceContaining("Vault Kerberos authentication requires HTTPS hostname verification");
    }

    @Test
    void testQualifiedClientsCoexistWithDatabaseClient()
            throws Exception
    {
        List<String> calls = Collections.synchronizedList(new ArrayList<>());
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            calls.add(path + " " + exchange.getRequestHeaders().getFirst("X-Vault-Token") + " " + exchange.getRequestHeaders().getFirst("X-Vault-Namespace"));
            String response;
            if (path.startsWith("/v1/database/")) {
                response = "{\"lease_id\":\"database/creds/role/lease\",\"lease_duration\":300,\"renewable\":true,\"data\":{\"username\":\"database-user\",\"password\":\"database-password\"}}";
            }
            else {
                response = path.startsWith("/v1/first/") ? "{\"data\":{\"key\":\"first-value\"}}" : "{\"data\":{\"data\":{\"key\":\"second-value\"}}}";
            }
            byte[] body = response.getBytes(UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();
        Injector injector = null;
        try {
            String endpoint = "http://127.0.0.1:" + server.getAddress().getPort();
            injector = new Bootstrap(
                    binder -> {
                        httpClientBinder(binder).bindHttpClient("database", ForVault.class);
                        configBinder(binder).bindConfig(VaultDatabaseConfig.class, "database");
                        binder.bind(VaultClient.class).in(SINGLETON);
                    },
                    new VaultModule("database"),
                    new VaultKvModule("first", First.class),
                    new VaultKvModule("second", Second.class))
                    .doNotInitializeLogging()
                    .quiet()
                    .setRequiredConfigurationProperties(ImmutableMap.<String, String>builder()
                            .put("database.endpoint", endpoint)
                            .put("database.token", "database-token")
                            .put("database.namespace", "database-namespace")
                            .put("database.role", "role")
                            .put("first.endpoint", endpoint)
                            .put("first.token", "first-token")
                            .put("first.namespace", "first-namespace")
                            .put("first.kv.mount", "first")
                            .put("first.kv.version", "1")
                            .put("first.http-client.request-timeout", "11s")
                            .put("first.http-client.https.hostname-verification", "false")
                            .put("second.endpoint", endpoint)
                            .put("second.token", "second-token")
                            .put("second.namespace", "second-namespace")
                            .put("second.kv.mount", "second")
                            .put("second.http-client.request-timeout", "12s")
                            .buildOrThrow())
                    .initialize();
            VaultKvClient firstClient = injector.getInstance(Key.get(VaultKvClient.class, First.class));
            VaultKvClient secondClient = injector.getInstance(Key.get(VaultKvClient.class, Second.class));
            VaultClient databaseClient = injector.getInstance(VaultClient.class);
            assertThat(firstClient.readSecretValue("path", "key")).isEqualTo("first-value");
            assertThat(secondClient.readSecretValue("path", "key")).isEqualTo("second-value");
            assertThat(databaseClient.readCredentials().username()).isEqualTo("database-user");
            assertThat(calls).containsExactly(
                    "/v1/first/path first-token first-namespace",
                    "/v1/second/data/path second-token second-namespace",
                    "/v1/database/creds/role database-token database-namespace");
            HttpClientConfig first = injector.getInstance(Key.get(HttpClientConfig.class, First.class));
            HttpClientConfig second = injector.getInstance(Key.get(HttpClientConfig.class, Second.class));
            assertThat(first.getRequestTimeout()).isEqualTo(new Duration(11, SECONDS));
            assertThat(second.getRequestTimeout()).isEqualTo(new Duration(12, SECONDS));
            assertThat(first.isVerifyHostname()).isFalse();
            assertThat(second.isVerifyHostname()).isTrue();
            assertThat(first.getConnectTimeout()).isEqualTo(new Duration(5, SECONDS));
            HttpClient firstHttp = injector.getInstance(Key.get(HttpClient.class, First.class));
            HttpClient secondHttp = injector.getInstance(Key.get(HttpClient.class, Second.class));
            HttpClient databaseHttp = injector.getInstance(Key.get(HttpClient.class, ForVault.class));
            injector.getInstance(LifeCycleManager.class).stop();
            assertThat(firstHttp.isClosed()).isTrue();
            assertThat(secondHttp.isClosed()).isTrue();
            assertThat(databaseHttp.isClosed()).isTrue();
            assertThatThrownBy(() -> firstClient.readSecret("path")).hasMessage("The Vault session is closed");
            assertThatThrownBy(() -> secondClient.readSecret("path")).hasMessage("The Vault session is closed");
            assertThatThrownBy(databaseClient::readCredentials).hasMessage("The Vault session is closed");
        }
        finally {
            if (injector != null) {
                injector.getInstance(LifeCycleManager.class).stop();
            }
            server.stop(0);
        }
    }

    @BindingAnnotation
    @Retention(RUNTIME)
    @Target({FIELD, PARAMETER, METHOD})
    private @interface First {}

    @BindingAnnotation
    @Retention(RUNTIME)
    @Target({FIELD, PARAMETER, METHOD})
    private @interface Second {}
}
