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

import com.google.inject.Injector;
import com.google.inject.Key;
import io.airlift.bootstrap.Bootstrap;
import io.airlift.spi.secrets.SecretProvider;
import io.airlift.spi.secrets.SecretProviderFactory;
import io.airlift.vault.VaultKvClient;
import io.airlift.vault.VaultKvModule;

import java.util.Map;

import static java.util.Objects.requireNonNull;

public class VaultSecretProviderFactory
        implements SecretProviderFactory
{
    @Override
    public String getName()
    {
        return "vault";
    }

    @Override
    public SecretProvider createSecretProvider(Map<String, String> config)
    {
        requireNonNull(config, "config is null");
        // SecretsPluginManager has already resolved these values. Bootstrap preserves
        // programmatic configuration literally, including any ${...} in a credential.
        Bootstrap bootstrap = new Bootstrap("vault-secrets", new VaultKvModule("vault", ForVaultSecrets.class))
                .doNotInitializeLogging()
                .disableSystemProperties()
                .withShutdownHook(false)
                .setRequiredConfigurationProperties(config);
        try {
            Injector injector = bootstrap.initialize();
            return new VaultSecretProvider(
                    injector.getInstance(Key.get(VaultKvClient.class, ForVaultSecrets.class)),
                    bootstrap);
        }
        catch (RuntimeException | Error failure) {
            try {
                bootstrap.close();
            }
            catch (RuntimeException ignored) {
                // Never expose cleanup failures, which can contain credentials or response bodies.
            }
            if (failure instanceof Error error) {
                throw error;
            }
            // Configuration conversion and Guice exceptions can contain the original value.
            throw new IllegalArgumentException("Invalid Vault secrets provider configuration");
        }
    }
}
