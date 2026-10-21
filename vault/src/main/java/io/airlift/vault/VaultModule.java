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

import com.google.inject.Binder;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.airlift.vault.auth.AppRoleLoginMethod;
import io.airlift.vault.auth.KerberosLoginMethod;
import io.airlift.vault.auth.KubernetesLoginMethod;
import io.airlift.vault.auth.LoginVaultTokenSupplier;
import io.airlift.vault.auth.VaultLoginMethod;
import io.airlift.vault.auth.VaultTokenSupplier;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.http.ForVault;
import io.airlift.vault.http.VaultHttp;

import static com.google.inject.Scopes.SINGLETON;
import static java.util.Objects.requireNonNull;

/**
 * Shared transport and authentication bindings. The caller supplies a {@link ForVault} HTTP client
 * and its engine client. Use a private scope when installing several sessions in one injector.
 */
public class VaultModule
        extends AbstractConfigurationAwareModule
{
    private final String configPrefix;

    public VaultModule(String configPrefix)
    {
        this.configPrefix = requireNonNull(configPrefix, "configPrefix is null");
    }

    @Override
    protected void setup(Binder binder)
    {
        VaultConnectionConfig config = buildConfigObject(VaultConnectionConfig.class, configPrefix);
        bindSession(binder, config);
    }

    static void bindSession(Binder binder, VaultConnectionConfig config)
    {
        binder.bind(VaultHttp.class).in(SINGLETON);
        binder.bind(VaultSession.class).in(SINGLETON);
        switch (config.getAuthMethod()) {
            case TOKEN -> binder.bind(VaultTokenSupplier.class).toInstance(VaultSession.configuredToken(config));
            case APPROLE -> bindLoginMethod(binder, AppRoleLoginMethod.class);
            case KUBERNETES -> bindLoginMethod(binder, KubernetesLoginMethod.class);
            case KERBEROS -> bindLoginMethod(binder, KerberosLoginMethod.class);
        }
    }

    private static void bindLoginMethod(Binder binder, Class<? extends VaultLoginMethod> loginMethod)
    {
        binder.bind(VaultLoginMethod.class).to(loginMethod).in(SINGLETON);
        binder.bind(VaultTokenSupplier.class).to(LoginVaultTokenSupplier.class).in(SINGLETON);
    }
}
