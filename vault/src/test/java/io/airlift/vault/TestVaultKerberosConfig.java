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

import io.airlift.configuration.ConfigurationFactory;
import io.airlift.http.client.HttpClientConfig;
import io.airlift.vault.config.VaultConnectionConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static io.airlift.testing.ValidationAssertions.assertValidates;
import static io.airlift.vault.enums.VaultAuthMethod.KERBEROS;
import static io.airlift.vault.enums.VaultAuthMethod.TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TestVaultKerberosConfig
{
    @TempDir
    Path directory;

    @Test
    void testPropertyMapping()
            throws Exception
    {
        Path keytab = Files.createFile(directory.resolve("client.keytab"));
        VaultConnectionConfig config = new ConfigurationFactory(Map.of(
                "endpoint", "https://bao.example:8200",
                "auth.method", "KERBEROS",
                "auth.kerberos.mount", "kerberos-trino",
                "auth.kerberos.role", "trino-config",
                "auth.kerberos.principal", "trino/node.example@EXAMPLE.COM",
                "auth.kerberos.keytab", keytab.toString(),
                "auth.kerberos.service-principal", "HTTP/bao.example@EXAMPLE.COM"))
                .build(VaultConnectionConfig.class);
        assertValidates(config);
        assertThat(config.getAuthMethod()).isEqualTo(KERBEROS);
        assertThat(config.getKerberosMount()).isEqualTo("kerberos-trino");
        assertThat(config.getKerberosRole()).contains("trino-config");
        assertThat(config.getKerberosPrincipal()).contains("trino/node.example@EXAMPLE.COM");
        assertThat(config.getKerberosKeytab()).contains(keytab.toFile());
        assertThat(config.getKerberosServicePrincipal()).contains("HTTP/bao.example@EXAMPLE.COM");
    }

    @Test
    void testMissingAndInvalidInputs()
            throws Exception
    {
        assertValidates(validConfig());
        assertThat(validConfig().setKerberosRole(" ").isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setKerberosPrincipal("trino").isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setKerberosServicePrincipal("HTTP/bao").isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setKerberosMount("../approle").isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setKerberosKeytab(directory.toFile()).isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setKerberosKeytab(null).isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setKerberosKeytab(directory.resolve("missing").toFile()).isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setAuthMethod(TOKEN).setToken("test").isKerberosConfigurationValid()).isFalse();
        assertThat(new VaultConnectionConfig().setToken("test").setKerberosMount("kerberos").isKerberosConfigurationValid()).isFalse();
        assertThat(validConfig().setToken("test").isTokenUnusedByOtherMethods()).isFalse();
        assertThat(validConfig().setAppRoleRoleId("other").isAppRoleConfigurationValid()).isFalse();
        assertThat(validConfig().setKubernetesRole("other").isKubernetesConfigurationValid()).isFalse();
    }

    @Test
    void testHttpsRequired()
            throws Exception
    {
        for (String endpoint : new String[] {"http://bao.example", "https:/missing-host", "https://user@bao.example", "https://bao.example?query", "https://bao.example#fragment"}) {
            assertThat(validConfig().setEndpoint(URI.create(endpoint)).isKerberosHttpsValid()).as(endpoint).isFalse();
        }
        assertThat(validConfig().isKerberosHttpsValid()).isTrue();
    }

    @Test
    void testOwnedSessionRequiresHostnameVerification()
            throws Exception
    {
        VaultConnectionConfig config = validConfig();
        assertThatThrownBy(() -> VaultSession.open(config, new HttpClientConfig().setVerifyHostname(false)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Vault Kerberos authentication requires HTTPS hostname verification");
        try (VaultSession ignored = VaultSession.open(config, new HttpClientConfig())) {
            // Creating a session validates TLS without performing a Kerberos login.
        }
    }

    private VaultConnectionConfig validConfig()
            throws Exception
    {
        Path keytab = directory.resolve("valid.keytab");
        if (!Files.exists(keytab)) {
            Files.createFile(keytab);
        }
        return new VaultConnectionConfig().setEndpoint(URI.create("https://bao.example:8200"))
                .setAuthMethod(KERBEROS).setKerberosRole("trino-config")
                .setKerberosPrincipal("trino/node.example@EXAMPLE.COM")
                .setKerberosKeytab(keytab.toFile())
                .setKerberosServicePrincipal("HTTP/bao.example@EXAMPLE.COM");
    }
}
