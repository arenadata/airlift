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

import io.airlift.configuration.secrets.SecretsPluginManager;
import io.airlift.configuration.secrets.SecretsResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static io.airlift.configuration.TomlConfiguration.createTomlConfiguration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs after package: the production ZIP must work with Airlift's isolated secrets classloader.
 */
public class ITVaultSecretsPlugin
{
    @TempDir
    Path temporaryDirectory;

    @Test
    public void testPackagedPluginWithIndependentNamespaces()
            throws Exception
    {
        Path plugins = temporaryDirectory.resolve("plugins");
        Path plugin = plugins.resolve("vault");
        Files.createDirectories(plugin);
        unpackPlugin(plugin);
        try (var files = Files.list(plugin)) {
            assertThat(files.map(path -> path.getFileName().toString()).toList())
                    .noneMatch(name -> name.contains("_trino-") || name.contains("_secrets-spi-"));
        }

        String literal = "  first-${ENV:KEEP_LITERAL}-secret  ";
        try (TestingVaultHttpServer first = new TestingVaultHttpServer(200, "{\"data\":{\"data\":{\"password\":\"" + literal + "\"}}}");
                TestingVaultHttpServer second = new TestingVaultHttpServer(200, "{\"data\":{\"password\":\"second-secret\"}}")) {
            Path configuration = temporaryDirectory.resolve("secrets.toml");
            Files.writeString(configuration,
                    """
                    secrets-plugins-dir = "%s"
                    [first]
                    secrets-provider.name = "vault"
                    vault.endpoint = "%s"
                    vault.token = "${ENV:VAULT_SECRETS_TEST_TOKEN}"
                    [second]
                    secrets-provider.name = "vault"
                    vault.endpoint = "%s"
                    vault.token = "second-token"
                    vault.kv.mount = "legacy"
                    vault.kv.version = "1"
                    """.formatted(plugins, first.endpoint(), second.endpoint()));
            try (SecretsPluginManager manager = new SecretsPluginManager(createTomlConfiguration(configuration.toFile()))) {
                manager.installPlugins();
                manager.load();
                SecretsResolver resolver = manager.getSecretsResolver();
                assertThat(resolver.getResolvedConfiguration(Map.of(
                        "internal-communication.shared-secret", "${first:server#password}",
                        "connection-password", "${second:database#password}")))
                        .containsEntry("internal-communication.shared-secret", literal)
                        .containsEntry("connection-password", "second-secret");
                assertThat(first.tokens()).containsExactly("test-${ENV:KEEP_LITERAL}");
                assertThat(second.tokens()).containsExactly("second-token");
                assertThat(second.paths()).containsExactly("/v1/legacy/database");
            }
        }
    }

    @Test
    public void testPackagedPluginWithOpenBaoKvVersionsRotationAndTokenFile()
            throws Exception
    {
        Path plugins = temporaryDirectory.resolve("openbao-plugins");
        Path plugin = plugins.resolve("vault");
        Files.createDirectories(plugin);
        unpackPlugin(plugin);
        String literal = "  first-${ENV:KEEP_LITERAL}-${vault:also#literal}  ";
        try (TestingOpenBaoServer server = new TestingOpenBaoServer()) {
            server.start();
            server.write("secret/data/trino/server", "{\"data\":{\"password\":\"" + literal + "\"}}");
            server.write("sys/mounts/legacy", "{\"type\":\"kv\",\"options\":{\"version\":\"1\"}}");
            server.write("legacy/trino/catalog", "{\"password\":\"legacy-secret\"}");
            server.createReadToken("first-reader", "secret/data/*");
            server.createReadToken("second-reader", "legacy/*");
            Path tokenFile = temporaryDirectory.resolve("token");
            Files.writeString(tokenFile, "first-reader");
            Path configuration = temporaryDirectory.resolve("openbao-secrets.toml");
            Files.writeString(configuration,
                    """
                    secrets-plugins-dir = "%s"
                    [first]
                    secrets-provider.name = "vault"
                    vault.endpoint = "%s"
                    vault.token-file = "%s"
                    [second]
                    secrets-provider.name = "vault"
                    vault.endpoint = "%s"
                    vault.token = "second-reader"
                    vault.kv.mount = "legacy"
                    vault.kv.version = "1"
                    """.formatted(plugins, server.endpoint(), tokenFile, server.endpoint()));
            try (SecretsPluginManager manager = new SecretsPluginManager(createTomlConfiguration(configuration.toFile()))) {
                manager.installPlugins();
                manager.load();
                SecretsResolver resolver = manager.getSecretsResolver();
                assertThat(resolver.getResolvedConfiguration(Map.of(
                        "internal-communication.shared-secret", "${first:trino/server#password}",
                        "connection-password", "${second:trino/catalog#password}")))
                        .containsEntry("internal-communication.shared-secret", literal)
                        .containsEntry("connection-password", "legacy-secret");
                server.write("secret/data/trino/server", "{\"data\":{\"password\":\"second-secret\"}}");
                assertThat(resolver.resolveSecret("first", "trino/server#password")).isEqualTo("second-secret");
                Files.writeString(tokenFile, "invalid-token");
                assertThatThrownBy(() -> resolver.resolveSecret("first", "trino/server#password"))
                        .hasMessage("Unable to resolve Vault secret (REFUSED, HTTP 403)")
                        .hasNoCause();
                // Failing or reloading the first namespace cannot change the second namespace.
                assertThat(resolver.resolveSecret("second", "trino/catalog#password")).isEqualTo("legacy-secret");
                Files.writeString(tokenFile, "first-reader");
                assertThat(resolver.resolveSecret("first", "trino/server#password")).isEqualTo("second-secret");
                server.write("secret/delete/trino/server", "{\"versions\":[2]}");
                assertThatThrownBy(() -> resolver.resolveSecret("first", "trino/server#password"))
                        .hasMessageStartingWith("Unable to resolve Vault secret (REFUSED")
                        .hasNoCause();
            }
            // Supplied tokens remain owned by the caller after both providers are closed.
            server.assertTokenExists("first-reader");
            server.assertTokenExists("second-reader");
        }
    }

    private static void unpackPlugin(Path target)
            throws IOException
    {
        Path archive = Path.of(System.getProperty("vault.plugin.zip"));
        assertThat(archive).isRegularFile();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(archive))) {
            for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                Path entryPath = Path.of(entry.getName());
                if (entryPath.getNameCount() == 1 && entry.isDirectory()) {
                    continue;
                }
                Path destination = target.resolve(entryPath.subpath(1, entryPath.getNameCount())).normalize();
                if (!destination.startsWith(target)) {
                    throw new IOException("Invalid archive entry");
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(destination);
                }
                else {
                    Files.createDirectories(destination.getParent());
                    Files.copy(zip, destination);
                }
            }
        }
        try (var files = Files.walk(target)) {
            for (Path jar : files.filter(path -> path.toString().endsWith(".jar")).toList()) {
                try (JarFile contents = new JarFile(jar.toFile())) {
                    assertThat(contents.stream().map(ZipEntry::getName).toList())
                            .noneMatch(name -> name.startsWith("io/trino/") || name.startsWith("io/airlift/spi/secrets/"));
                }
            }
        }
    }
}
