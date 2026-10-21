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
import com.google.common.collect.ImmutableSet;
import com.google.inject.Binder;
import io.airlift.bootstrap.Bootstrap;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.airlift.vault.config.VaultConnectionConfig;
import jakarta.validation.constraints.AssertTrue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import static io.airlift.configuration.testing.ConfigAssertions.assertFullMapping;
import static io.airlift.configuration.testing.ConfigAssertions.assertRecordedDefaults;
import static io.airlift.configuration.testing.ConfigAssertions.recordDefaults;
import static io.airlift.testing.ValidationAssertions.assertFailsValidation;
import static io.airlift.testing.ValidationAssertions.assertValidates;
import static io.airlift.vault.enums.VaultAuthMethod.APPROLE;
import static io.airlift.vault.enums.VaultAuthMethod.KUBERNETES;
import static io.airlift.vault.enums.VaultAuthMethod.TOKEN;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The properties describing the server and the role it hands credentials out from.
 * <p>
 * The {@code @Config} names of this class carry no prefix, so the property maps below are spelled
 * without one; a catalog never sees these names. What a catalog does see is produced by the prefix the
 * consumer binds with, and that is what
 * {@link #testPropertiesOfTheCatalogReachTheConfigThroughThePrefix} covers.
 */
public class TestVaultConfig
{
    private static final Set<String> APPROLE_PROPERTIES = ImmutableSet.of(
            "auth.approle.mount",
            "auth.approle.role-id",
            "auth.approle.secret-id",
            "auth.approle.secret-id-file");
    private static final Set<String> KUBERNETES_PROPERTIES = ImmutableSet.of(
            "auth.kubernetes.mount",
            "auth.kubernetes.role",
            "auth.kubernetes.service-account-token-file");

    @Test
    public void testMountsOfAnUnusedAuthMethodAreRejected()
    {
        // a mount carries a default, which is why the invariant looks at whether the property was
        // named at all: a catalog that spells out an AppRole mount and then authenticates with a
        // token has configured something nothing reads
        assertFailsValidation(
                new VaultConnectionConfig()
                        .setEndpoint(URI.create("http://openbao:8200"))
                        .setToken("hvs.CAESITestToken")
                        .setAppRoleMount("approle"),
                "appRoleConfigurationValid",
                "'vault.auth.approle.role-id' and exactly one of 'vault.auth.approle.secret-id' or 'vault.auth.approle.secret-id-file' must be set when, and only when, vault.auth.method is APPROLE",
                AssertTrue.class);

        assertFailsValidation(
                new VaultConnectionConfig()
                        .setEndpoint(URI.create("http://openbao:8200"))
                        .setToken("hvs.CAESITestToken")
                        .setKubernetesMount("kubernetes"),
                "kubernetesConfigurationValid",
                "'vault.auth.kubernetes.role' must be set when, and only when, vault.auth.method is KUBERNETES",
                AssertTrue.class);
    }

    @Test
    public void testDefaults()
    {
        assertRecordedDefaults(recordDefaults(VaultConnectionConfig.class)
                .setEndpoint(null)
                .setAuthMethod(TOKEN)
                .setToken(null)
                .setTokenFile(null)
                .setAppRoleMount("approle")
                .setAppRoleRoleId(null)
                .setAppRoleSecretId(null)
                .setAppRoleSecretIdFile(null)
                .setKubernetesMount("kubernetes")
                .setKubernetesRole(null)
                .setKubernetesServiceAccountTokenFile(null)
                .setNamespace(null));
    }

    @Test
    public void testExplicitPropertyMappings()
    {
        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .putAll(commonProperties())
                .put("token", "root-token")
                .buildOrThrow();

        VaultConnectionConfig expected = expectedCommonConfig()
                .setToken("root-token");

        // vault.token and vault.token-file are mutually exclusive, the file variant is tested below,
        // and the properties of the other authentication methods have their own tests
        assertFullMapping(properties, expected, skipping("token-file", "auth.method"));
    }

    @Test
    public void testTokenFilePropertyMapping(@TempDir Path tempDir)
            throws Exception
    {
        Path tokenFile = Files.createFile(tempDir.resolve("vault-token"));

        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .putAll(commonProperties())
                .put("token-file", tokenFile.toString())
                .buildOrThrow();

        VaultConnectionConfig expected = expectedCommonConfig()
                .setTokenFile(tokenFile.toFile());

        assertFullMapping(properties, expected, skipping("token", "auth.method"));
    }

    @Test
    public void testAppRolePropertyMappings()
    {
        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .putAll(commonProperties())
                .put("auth.method", "APPROLE")
                .put("auth.approle.mount", "trino-approle")
                .put("auth.approle.role-id", "3b7d0f36-0a11-4f0e-9f6c-1f9c2a5f1c11")
                .put("auth.approle.secret-id", "8f2b2e1a-6b9e-4d70-9d6e-2b1d1f4a5c22")
                .buildOrThrow();

        VaultConnectionConfig expected = expectedCommonConfig()
                .setAuthMethod(APPROLE)
                .setAppRoleMount("trino-approle")
                .setAppRoleRoleId("3b7d0f36-0a11-4f0e-9f6c-1f9c2a5f1c11")
                .setAppRoleSecretId("8f2b2e1a-6b9e-4d70-9d6e-2b1d1f4a5c22");

        // the secret id file variant is covered by the validation test, the token properties belong
        // to the TOKEN method
        assertFullMapping(
                properties,
                expected,
                ImmutableSet.<String>builder()
                        .add("token", "token-file", "auth.approle.secret-id-file")
                        .addAll(KUBERNETES_PROPERTIES)
                        .build());
    }

    @Test
    public void testKubernetesPropertyMappings(@TempDir Path tempDir)
            throws Exception
    {
        Path serviceAccountTokenFile = Files.createFile(tempDir.resolve("service-account-token"));

        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .putAll(commonProperties())
                .put("auth.method", "KUBERNETES")
                .put("auth.kubernetes.mount", "trino-kubernetes")
                .put("auth.kubernetes.role", "trino-coordinator")
                .put("auth.kubernetes.service-account-token-file", serviceAccountTokenFile.toString())
                .buildOrThrow();

        VaultConnectionConfig expected = expectedCommonConfig()
                .setAuthMethod(KUBERNETES)
                .setKubernetesMount("trino-kubernetes")
                .setKubernetesRole("trino-coordinator")
                .setKubernetesServiceAccountTokenFile(serviceAccountTokenFile.toFile());

        assertFullMapping(
                properties,
                expected,
                ImmutableSet.<String>builder()
                        .add("token", "token-file")
                        .addAll(APPROLE_PROPERTIES)
                        .build());
    }

    /**
     * The prefix a consumer binds with is what turns these names into the ones a catalog file spells,
     * so a catalog keeps naming {@code vault.endpoint} and {@code vault.token}
     * exactly as it did while the class lived in the JDBC connector.
     */
    @Test
    public void testPropertiesOfTheCatalogReachTheConfigThroughThePrefix()
    {
        Map<String, String> properties = ImmutableMap.of(
                "vault.endpoint", "https://openbao.example.com:8200",
                "vault.token", "root-token");

        VaultConnectionConfig config = new Bootstrap(new AbstractConfigurationAwareModule()
        {
            @Override
            protected void setup(Binder binder)
            {
                buildConfigObject(VaultConnectionConfig.class, "vault");
            }
        })
                .doNotInitializeLogging()
                .quiet()
                .setRequiredConfigurationProperties(properties)
                .initialize()
                .getInstance(VaultConnectionConfig.class);

        assertThat(config.getEndpoint()).isEqualTo(URI.create("https://openbao.example.com:8200"));
        assertThat(config.getToken()).contains("root-token");
    }

    @Test
    public void testTokenAndTokenFileAreMutuallyExclusive(@TempDir Path tempDir)
            throws Exception
    {
        File tokenFile = Files.createFile(tempDir.resolve("vault-token")).toFile();
        String message = "Exactly one of 'vault.token' or 'vault.token-file' must be set";

        assertValidates(minimalConfig().setToken("root-token"));
        assertValidates(minimalConfig().setTokenFile(tokenFile));

        assertFailsValidation(minimalConfig(), "tokenConfigurationValid", message, AssertTrue.class);
        assertFailsValidation(
                minimalConfig().setToken("root-token").setTokenFile(tokenFile),
                "tokenConfigurationValid",
                message,
                AssertTrue.class);
    }

    @Test
    public void testAppRoleConfigurationValidation(@TempDir Path tempDir)
            throws Exception
    {
        File secretIdFile = Files.createFile(tempDir.resolve("secret-id")).toFile();
        String message = "'vault.auth.approle.role-id' and exactly one of 'vault.auth.approle.secret-id' or " +
                "'vault.auth.approle.secret-id-file' must be set when, and only when, vault.auth.method is APPROLE";

        assertValidates(appRoleConfig().setAppRoleSecretId("secret-id"));
        assertValidates(appRoleConfig().setAppRoleSecretIdFile(secretIdFile));

        // no token is needed, and none may be set
        assertFailsValidation(
                appRoleConfig().setAppRoleSecretId("secret-id").setToken("root-token"),
                "tokenUnusedByOtherMethods",
                "'vault.token' and 'vault.token-file' must not be set when vault.auth.method is not TOKEN",
                AssertTrue.class);

        assertFailsValidation(appRoleConfig(), "appRoleConfigurationValid", message, AssertTrue.class);
        assertFailsValidation(
                minimalConfig().setAuthMethod(APPROLE).setAppRoleSecretId("secret-id"),
                "appRoleConfigurationValid",
                message,
                AssertTrue.class);
        assertFailsValidation(
                appRoleConfig().setAppRoleSecretId("secret-id").setAppRoleSecretIdFile(secretIdFile),
                "appRoleConfigurationValid",
                message,
                AssertTrue.class);
        // a role id left over from an abandoned migration must not be silently ignored
        assertFailsValidation(
                minimalConfig().setToken("root-token").setAppRoleRoleId("role-id"),
                "appRoleConfigurationValid",
                message,
                AssertTrue.class);
    }

    @Test
    public void testKubernetesConfigurationValidation(@TempDir Path tempDir)
            throws Exception
    {
        File serviceAccountTokenFile = Files.createFile(tempDir.resolve("service-account-token")).toFile();
        String message = "'vault.auth.kubernetes.role' must be set when, and only when, vault.auth.method is KUBERNETES";

        // the service account token file is optional, the kubelet writes it to a known path
        assertValidates(minimalConfig().setAuthMethod(KUBERNETES).setKubernetesRole("trino"));
        assertValidates(minimalConfig()
                .setAuthMethod(KUBERNETES)
                .setKubernetesRole("trino")
                .setKubernetesServiceAccountTokenFile(serviceAccountTokenFile));

        assertFailsValidation(
                minimalConfig().setAuthMethod(KUBERNETES),
                "kubernetesConfigurationValid",
                message,
                AssertTrue.class);
        assertFailsValidation(
                minimalConfig().setToken("root-token").setKubernetesRole("trino"),
                "kubernetesConfigurationValid",
                message,
                AssertTrue.class);
    }

    /**
     * A login method fetches its own token, so a token left in the catalog is never sent anywhere. It
     * has to be reported rather than ignored: silence would let an operator believe the catalog still
     * talks to the server with the token they can see in the file, and keep a credential that nothing
     * revokes lying around. The AppRole case with {@code vault.token} lives in
     * {@link #testAppRoleConfigurationValidation}; what is pinned here is that the file variant counts
     * the same and that Kubernetes is no exception.
     */
    @Test
    public void testTokenPropertiesAreRefusedByTheOtherAuthMethods(@TempDir Path tempDir)
            throws Exception
    {
        File tokenFile = Files.createFile(tempDir.resolve("vault-token")).toFile();
        String message = "'vault.token' and 'vault.token-file' must not be set when vault.auth.method is not TOKEN";

        assertFailsValidation(
                appRoleConfig().setAppRoleSecretId("secret-id").setTokenFile(tokenFile),
                "tokenUnusedByOtherMethods",
                message,
                AssertTrue.class);
        assertFailsValidation(
                kubernetesConfig().setToken("root-token"),
                "tokenUnusedByOtherMethods",
                message,
                AssertTrue.class);
        assertFailsValidation(
                kubernetesConfig().setTokenFile(tokenFile),
                "tokenUnusedByOtherMethods",
                message,
                AssertTrue.class);
    }

    /**
     * The "and only when" half of both invariants, for the properties whose leftovers are the easy ones
     * to miss: a secret id or a service account token file that outlived the method it was written for
     * says the catalog is authenticating in a different way than its author thinks, so it is refused
     * instead of being dropped on the floor.
     */
    @Test
    public void testPropertiesOfAnUnselectedAuthMethodAreRefused(@TempDir Path tempDir)
            throws Exception
    {
        File secretIdFile = Files.createFile(tempDir.resolve("secret-id")).toFile();
        File serviceAccountTokenFile = Files.createFile(tempDir.resolve("service-account-token")).toFile();
        String appRoleMessage = "'vault.auth.approle.role-id' and exactly one of 'vault.auth.approle.secret-id' or " +
                "'vault.auth.approle.secret-id-file' must be set when, and only when, vault.auth.method is APPROLE";
        String kubernetesMessage = "'vault.auth.kubernetes.role' must be set when, and only when, vault.auth.method is KUBERNETES";

        assertFailsValidation(
                minimalConfig().setToken("root-token").setAppRoleSecretId("secret-id"),
                "appRoleConfigurationValid",
                appRoleMessage,
                AssertTrue.class);
        assertFailsValidation(
                minimalConfig().setToken("root-token").setAppRoleSecretIdFile(secretIdFile),
                "appRoleConfigurationValid",
                appRoleMessage,
                AssertTrue.class);
        assertFailsValidation(
                kubernetesConfig().setAppRoleRoleId("3b7d0f36-0a11-4f0e-9f6c-1f9c2a5f1c11"),
                "appRoleConfigurationValid",
                appRoleMessage,
                AssertTrue.class);

        assertFailsValidation(
                minimalConfig().setToken("root-token").setKubernetesServiceAccountTokenFile(serviceAccountTokenFile),
                "kubernetesConfigurationValid",
                kubernetesMessage,
                AssertTrue.class);
        assertFailsValidation(
                appRoleConfig().setAppRoleSecretId("secret-id").setKubernetesRole("trino"),
                "kubernetesConfigurationValid",
                kubernetesMessage,
                AssertTrue.class);
    }

    private static Set<String> skipping(String... properties)
    {
        return ImmutableSet.<String>builder()
                .add(properties)
                .addAll(APPROLE_PROPERTIES)
                .addAll(KUBERNETES_PROPERTIES)
                .build();
    }

    private static Map<String, String> commonProperties()
    {
        return ImmutableMap.<String, String>builder()
                .put("endpoint", "https://openbao.example.com:8200")
                .put("namespace", "team-analytics")
                .buildOrThrow();
    }

    private static VaultConnectionConfig expectedCommonConfig()
    {
        return new VaultConnectionConfig()
                .setEndpoint(URI.create("https://openbao.example.com:8200"))
                .setNamespace("team-analytics");
    }

    private static VaultConnectionConfig minimalConfig()
    {
        return new VaultConnectionConfig()
                .setEndpoint(URI.create("https://openbao.example.com:8200"));
    }

    private static VaultConnectionConfig appRoleConfig()
    {
        return minimalConfig()
                .setAuthMethod(APPROLE)
                .setAppRoleRoleId("3b7d0f36-0a11-4f0e-9f6c-1f9c2a5f1c11");
    }

    private static VaultConnectionConfig kubernetesConfig()
    {
        return minimalConfig()
                .setAuthMethod(KUBERNETES)
                .setKubernetesRole("trino-coordinator");
    }
}
