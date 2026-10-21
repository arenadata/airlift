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
package io.airlift.secrets.keystore;

import io.airlift.spi.secrets.SecretProvider;
import io.airlift.testing.TempFile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.parallel.Isolated;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(PER_CLASS)
@Isolated("Changes keystore system properties")
final class TestKeystoreSecretProvider
{
    private TempFile keystoreFile;

    private KeystoreSecretProvider secretProvider;

    @BeforeAll
    public void setup()
            throws Exception
    {
        keystoreFile = new TempFile();
        writeKeystore(keystoreFile, "password", "value");

        secretProvider = new KeystoreSecretProvider(new KeystoreSecretProviderConfig()
                .setKeyStoreType("jks")
                .setKeyStoreFilePath(keystoreFile.file().getAbsolutePath())
                .setKeyStorePassword("password"));
    }

    @AfterAll
    public void teardown()
    {
        if (keystoreFile != null) {
            keystoreFile.close();
        }
    }

    @Test
    public void testConfigurationResolver()
    {
        assertThat(secretProvider.resolveSecretValue("key")).isEqualTo("value");
    }

    @Test
    public void testConfigurationResolverWithInvalidKey()
    {
        assertThatThrownBy(() -> secretProvider.resolveSecretValue("invalid_key"))
                .hasMessageContaining("Key not found in keystore: invalid_key");
    }

    @Test
    public void testKeystoreWithInvalidPassword()
    {
        assertThatThrownBy(() ->
                new KeystoreSecretProvider(new KeystoreSecretProviderConfig()
                        .setKeyStoreType("jks")
                        .setKeyStoreFilePath(keystoreFile.file().getAbsolutePath())
                        .setKeyStorePassword("invalid_password"))
                        .resolveSecretValue("key"))
                .hasMessageContaining("Failed PKCS12 integrity checking");
    }

    @Test
    public void testFactoryProviderLifecycle()
            throws Exception
    {
        try (SecretProvider provider = new KeystoreSecretProviderFactory().createSecretProvider(configuration("password"))) {
            assertThat(provider.resolveSecretValue("key")).isEqualTo("value");
            provider.close();
            provider.close();
            assertThatThrownBy(() -> provider.resolveSecretValue("key"))
                    .hasMessage("Keystore secrets provider is closed");
        }
    }

    @Test
    public void testFactoryPreservesSystemPropertyOverrides()
            throws Exception
    {
        String previous = System.setProperty("keystore-password", "password");
        try (SecretProvider provider = new KeystoreSecretProviderFactory().createSecretProvider(configuration("incorrect-password"))) {
            assertThat(provider.resolveSecretValue("key")).isEqualTo("value");
        }
        finally {
            if (previous == null) {
                System.clearProperty("keystore-password");
            }
            else {
                System.setProperty("keystore-password", previous);
            }
        }
    }

    @Test
    public void testFactoryPreservesLiteralConfigurationAndSecretValues()
            throws Exception
    {
        String password = "literal-${ENV:DO_NOT_RESOLVE_PASSWORD_AGAIN}";
        String value = "  ${ENV:DO_NOT_RESOLVE_SECRET_AGAIN}  ";
        try (TempFile file = new TempFile()) {
            writeKeystore(file, password, value);
            try (SecretProvider provider = new KeystoreSecretProviderFactory().createSecretProvider(Map.of(
                    "keystore-type", "jks",
                    "keystore-file-path", file.file().getAbsolutePath(),
                    "keystore-password", password))) {
                assertThat(provider.resolveSecretValue("key")).isEqualTo(value);
            }
        }
    }

    private Map<String, String> configuration(String password)
    {
        return Map.of(
                "keystore-type", "jks",
                "keystore-file-path", keystoreFile.file().getAbsolutePath(),
                "keystore-password", password);
    }

    private static void writeKeystore(TempFile file, String password, String value)
            throws Exception
    {
        char[] passwordCharacters = password.toCharArray();
        KeyStore keystore = KeyStore.getInstance("pkcs12");
        keystore.load(null, passwordCharacters);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
        keystore.setEntry(
                "key",
                new KeyStore.SecretKeyEntry(factory.generateSecret(new PBEKeySpec(value.toCharArray()))),
                new KeyStore.PasswordProtection(passwordCharacters));
        try (FileOutputStream outputStream = new FileOutputStream(file.file())) {
            keystore.store(outputStream, passwordCharacters);
        }
    }
}
