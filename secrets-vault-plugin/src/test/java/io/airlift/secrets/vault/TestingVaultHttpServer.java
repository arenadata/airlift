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

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

import static java.nio.charset.StandardCharsets.UTF_8;

final class TestingVaultHttpServer
        implements AutoCloseable
{
    private final HttpServer server;
    private final List<String> tokens = new CopyOnWriteArrayList<>();
    private final List<String> paths = new CopyOnWriteArrayList<>();

    TestingVaultHttpServer(int status, String response)
            throws IOException
    {
        this(_ -> new Response(status, response));
    }

    TestingVaultHttpServer(Function<String, Response> responses)
            throws IOException
    {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/", exchange -> {
            try (exchange) {
                String path = exchange.getRequestURI().getPath();
                paths.add(path);
                String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
                if (token != null) {
                    tokens.add(token);
                }
                Response response = responses.apply(path);
                byte[] body = response.body().getBytes(UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(response.status(), body.length);
                exchange.getResponseBody().write(body);
            }
        });
        server.start();
    }

    String endpoint()
    {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    List<String> tokens()
    {
        return List.copyOf(tokens);
    }

    List<String> paths()
    {
        return List.copyOf(paths);
    }

    @Override
    public void close()
    {
        server.stop(0);
    }

    record Response(int status, String body) {}
}
