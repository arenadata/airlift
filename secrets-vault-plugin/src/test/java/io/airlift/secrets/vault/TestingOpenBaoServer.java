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
package io.airlift.secrets.vault;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

final class TestingOpenBaoServer
        implements AutoCloseable
{
    private static final int PORT = 8200;
    private static final String ROOT_TOKEN = "testing-root-token";

    private final GenericContainer<?> container = new GenericContainer<>(DockerImageName.parse("openbao/openbao:2.6.1"))
            .withExposedPorts(PORT)
            .withEnv("BAO_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
            .withEnv("BAO_DEV_LISTEN_ADDRESS", "0.0.0.0:" + PORT)
            .withStartupAttempts(3)
            .waitingFor(Wait.forHttp("/v1/sys/health").forPort(PORT).forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(2));

    void start()
    {
        container.start();
    }

    String endpoint()
    {
        return "http://%s:%s".formatted(container.getHost(), container.getMappedPort(PORT));
    }

    void createReadToken(String token, String path)
            throws Exception
    {
        write("sys/policies/acl/" + token, """
                {"policy":"path \\"%s\\" { capabilities = [\\"read\\"] }"}
                """.formatted(path));
        write("auth/token/create", """
                {"id":"%s","policies":["%s"],"no_default_policy":true}
                """.formatted(token, token));
    }

    void assertTokenExists(String token)
            throws Exception
    {
        write("auth/token/lookup", "{\"token\":\"" + token + "\"}");
    }

    void write(String path, String body)
            throws Exception
    {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint() + "/v1/" + path))
                    .header("X-Vault-Token", ROOT_TOKEN)
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofString(body, UTF_8))
                    .build();
            assertThat(client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()).isIn(200, 204);
        }
    }

    @Override
    public void close()
    {
        container.stop();
    }
}
