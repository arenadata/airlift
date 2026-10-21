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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import static java.util.Collections.list;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Isolated("Changes process-wide logging levels to exercise the documented Vault logging policy")
public class TestVaultLogging
{
    @Test
    public void testDocumentedLoggingPolicyDoesNotExposeSecrets()
            throws Exception
    {
        String token = "private-login-token-logging-test";
        String secretId = "private-approle-secret-id-logging-test";
        String value = "private-kv-value-logging-test";
        List<String> messages = new CopyOnWriteArrayList<>();
        Handler handler = new Handler()
        {
            private final SimpleFormatter formatter = new SimpleFormatter();

            @Override
            public void publish(LogRecord record)
            {
                messages.add(formatter.format(record));
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        handler.setLevel(Level.ALL);
        Logger root = Logger.getLogger("");
        Logger jetty = Logger.getLogger("org.eclipse.jetty");
        Logger vault = Logger.getLogger("io.airlift.vault");
        Map<Logger, Level> originalLevels = new HashMap<>();
        originalLevels.put(jetty, jetty.getLevel());
        originalLevels.put(vault, vault.getLevel());
        // The documented policy requires removing child overrides as well.
        for (String name : list(LogManager.getLogManager().getLoggerNames())) {
            if (name.startsWith("org.eclipse.jetty.")) {
                Logger logger = Logger.getLogger(name);
                originalLevels.put(logger, logger.getLevel());
                logger.setLevel(null);
            }
        }
        jetty.setLevel(Level.INFO);
        vault.setLevel(Level.FINE);
        root.addHandler(handler);
        try (TestingVaultHttpServer server = new TestingVaultHttpServer(path -> switch (path) {
            case "/v1/auth/approle/login" -> new TestingVaultHttpServer.Response(
                    200, "{\"auth\":{\"client_token\":\"" + token + "\",\"renewable\":false,\"lease_duration\":3600}}");
            case "/v1/auth/token/revoke-self" -> new TestingVaultHttpServer.Response(200, "{}");
            case "/v1/secret/data/failure" -> new TestingVaultHttpServer.Response(503, "{\"errors\":[\"" + value + "\"]}");
            default -> new TestingVaultHttpServer.Response(200, "{\"data\":{\"data\":{\"password\":\"" + value + "\"}}}");
        });
                VaultSecretProvider provider = (VaultSecretProvider) new VaultSecretProviderFactory().createSecretProvider(Map.of(
                        "vault.endpoint", server.endpoint(),
                        "vault.auth.method", "APPROLE",
                        "vault.auth.approle.role-id", "logging-test-role",
                        "vault.auth.approle.secret-id", secretId))) {
            assertThat(provider.resolveSecretValue("success#password")).isEqualTo(value);
            assertThatThrownBy(() -> provider.resolveSecretValue("failure#password"))
                    .hasMessage("Unable to resolve Vault secret (UNAVAILABLE, HTTP 503)")
                    .hasNoCause();
            provider.close();
            vault.fine("safe logging policy test marker");
            assertThat(String.join("\n", messages))
                    .contains("safe logging policy test marker")
                    .doesNotContain(token, secretId, value);
        }
        finally {
            root.removeHandler(handler);
            originalLevels.forEach(Logger::setLevel);
        }
    }
}
