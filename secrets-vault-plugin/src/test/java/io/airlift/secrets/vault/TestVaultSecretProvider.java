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

import io.airlift.configuration.secrets.SecretsResolver;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestVaultSecretProvider
{
    @Test
    public void testIndependentProvidersAndLiteralInterpolation()
            throws Exception
    {
        String literal = "${ENV:DO_NOT_EXPAND}";
        try (TestingVaultHttpServer first = new TestingVaultHttpServer(200, "{\"data\":{\"data\":{\"password\":\"" + literal + "\"}}}");
                TestingVaultHttpServer second = new TestingVaultHttpServer(200, "{\"data\":{\"data\":{\"password\":\"second-secret\"}}}");
                VaultSecretProvider firstProvider = createProvider(first.endpoint(), literal);
                VaultSecretProvider secondProvider = createProvider(second.endpoint(), "second-token")) {
            SecretsResolver resolver = new SecretsResolver(Map.of("first", firstProvider, "second", secondProvider));
            assertThat(resolver.getResolvedConfiguration(Map.of(
                    "internal-communication.shared-secret", "${first:trino/server#password}",
                    "connection-password", "${second:catalog/database#password}")))
                    .containsEntry("internal-communication.shared-secret", literal)
                    .containsEntry("connection-password", "second-secret");
            assertThat(first.tokens()).containsExactly(literal);
            assertThat(second.tokens()).containsExactly("second-token");
            assertThat(first.paths()).containsExactly("/v1/secret/data/trino/server");
        }
    }

    @Test
    public void testReferenceValidationAndClosedProvider()
            throws Exception
    {
        try (TestingVaultHttpServer server = new TestingVaultHttpServer(200, "{}");
                VaultSecretProvider provider = createProvider(server.endpoint(), "token")) {
            for (String reference : List.of("", "path", "#key", "path#", "path#key#extra")) {
                assertThatThrownBy(() -> provider.resolveSecretValue(reference))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessage("Vault secret reference must have the form path#key")
                        .hasNoCause();
            }
            assertThat(server.paths()).isEmpty();
            provider.close();
            assertThatThrownBy(() -> provider.resolveSecretValue("path#key"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Vault secrets provider is closed");
        }
    }

    @Test
    public void testFailureDoesNotExposeSecretsAndRestoresClassLoader()
            throws Exception
    {
        try (TestingVaultHttpServer server = new TestingVaultHttpServer(403, "{\"errors\":[\"secret-response-body\"]}");
                VaultSecretProvider provider = createProvider(server.endpoint(), "private-token")) {
            ClassLoader original = Thread.currentThread().getContextClassLoader();
            assertThatThrownBy(() -> provider.resolveSecretValue("private/path#password"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unable to resolve Vault secret (REFUSED, HTTP 403)")
                    .hasNoCause();
            assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(original);
        }
    }

    @Test
    public void testStrictConfigurationAndRedactedErrors()
    {
        Map<String, String> properties = new HashMap<>(Map.of(
                "vault.endpoint", "http://127.0.0.1:1",
                "vault.token", "private-token"));
        properties.put("vault.typo", "private-value");
        assertThatThrownBy(() -> new VaultSecretProviderFactory().createSecretProvider(properties))
                .hasMessage("Invalid Vault secrets provider configuration")
                .hasNoCause();
        properties.remove("vault.typo");
        properties.put("vault.kv.version", "private-invalid-value");
        assertThatThrownBy(() -> new VaultSecretProviderFactory().createSecretProvider(properties))
                .hasMessage("Invalid Vault secrets provider configuration")
                .hasNoCause();
    }

    @Test
    public void testSafeKvFailureReasons()
            throws Exception
    {
        Map<String, String> failures = Map.of(
                "{\"data\":{\"data\":{}}}", "field is missing or is not a string",
                "{\"data\":{\"data\":{\"password\":123}}}", "field is missing or is not a string",
                "{}", "invalid KV response",
                "invalid-json-private-payload", "invalid KV response",
                "{\"data\":{\"data\":{},\"metadata\":{\"destroyed\":true}}}", "secret version was deleted or destroyed");
        for (Map.Entry<String, String> failure : failures.entrySet()) {
            try (TestingVaultHttpServer server = new TestingVaultHttpServer(200, failure.getKey());
                    VaultSecretProvider provider = createProvider(server.endpoint(), "private-token")) {
                assertThatThrownBy(() -> provider.resolveSecretValue("private/path#password"))
                        .hasMessage("Unable to resolve Vault secret: " + failure.getValue())
                        .hasNoCause();
            }
        }
    }

    @Test
    public void testUnavailableServerIsDistinctFromRefusedSecret()
            throws Exception
    {
        try (TestingVaultHttpServer server = new TestingVaultHttpServer(503, "{\"errors\":[\"private-error-body\"]}");
                VaultSecretProvider provider = createProvider(server.endpoint(), "private-token")) {
            assertThatThrownBy(() -> provider.resolveSecretValue("private/path#password"))
                    .hasMessage("Unable to resolve Vault secret (UNAVAILABLE, HTTP 503)")
                    .hasNoCause();
        }
    }

    @Test
    public void testOwnedAppRoleTokenRevokedOnClose()
            throws Exception
    {
        try (TestingVaultHttpServer server = new TestingVaultHttpServer(path -> switch (path) {
            case "/v1/auth/approle/login" -> new TestingVaultHttpServer.Response(
                    200,
                    "{\"auth\":{\"client_token\":\"owned-token\",\"renewable\":false,\"lease_duration\":3600}}");
            case "/v1/auth/token/revoke-self" -> new TestingVaultHttpServer.Response(200, "{}");
            default -> new TestingVaultHttpServer.Response(200, "{\"data\":{\"data\":{\"password\":\"value\"}}}");
        })) {
            try (VaultSecretProvider provider = (VaultSecretProvider) new VaultSecretProviderFactory().createSecretProvider(Map.of(
                    "vault.endpoint", server.endpoint(),
                    "vault.auth.method", "APPROLE",
                    "vault.auth.approle.role-id", "role",
                    "vault.auth.approle.secret-id", "secret"))) {
                assertThat(provider.resolveSecretValue("path#password")).isEqualTo("value");
            }
            assertThat(server.paths()).containsExactly(
                    "/v1/auth/approle/login",
                    "/v1/secret/data/path",
                    "/v1/auth/token/revoke-self");
        }
    }

    private static VaultSecretProvider createProvider(String endpoint, String token)
    {
        return (VaultSecretProvider) new VaultSecretProviderFactory().createSecretProvider(Map.of(
                "vault.endpoint", endpoint,
                "vault.token", token));
    }
}
