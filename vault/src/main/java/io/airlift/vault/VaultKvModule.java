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
import com.google.inject.Key;
import com.google.inject.PrivateBinder;
import com.google.inject.Provider;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.airlift.http.client.HttpClient;
import io.airlift.units.Duration;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.config.VaultKvConfig;

import java.lang.annotation.Annotation;

import static com.google.inject.Scopes.SINGLETON;
import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * An isolated, qualified KV client, including its own HTTP and authentication state.
 */
public final class VaultKvModule
        extends AbstractConfigurationAwareModule
{
    private final String configPrefix;
    private final Class<? extends Annotation> qualifier;

    public VaultKvModule(String configPrefix, Class<? extends Annotation> qualifier)
    {
        this.configPrefix = requireNonNull(configPrefix, "configPrefix is null");
        this.qualifier = requireNonNull(qualifier, "qualifier is null");
    }

    @Override
    protected void setup(Binder binder)
    {
        // Configuration discovery does not traverse private Guice elements. Register qualified
        // configuration and HTTP bindings in the parent, then keep the session graph private.
        VaultConnectionConfig connectionConfig = buildConfigObject(Key.get(VaultConnectionConfig.class, qualifier), VaultConnectionConfig.class, configPrefix);
        VaultKvConfig kvConfig = buildConfigObject(Key.get(VaultKvConfig.class, qualifier), VaultKvConfig.class, configPrefix);
        httpClientBinder(binder).bindHttpClient(configPrefix, qualifier)
                .withConfigDefaults(config -> {
                    config.setConnectTimeout(new Duration(5, SECONDS));
                    config.setRequestTimeout(new Duration(10, SECONDS));
                });
        Provider<HttpClient> httpClient = binder.getProvider(Key.get(HttpClient.class, qualifier));
        PrivateBinder privateBinder = binder.newPrivateBinder();
        // Qualify private keys too: Guice cannot shadow bindings from a database VaultModule
        // installed in the parent injector.
        Key<VaultSession> sessionKey = Key.get(VaultSession.class, qualifier);
        privateBinder.bind(sessionKey).toProvider(() -> VaultSession.borrowed(httpClient.get(), connectionConfig)).in(SINGLETON);
        Provider<VaultSession> session = privateBinder.getProvider(sessionKey);
        privateBinder.bind(VaultKvClient.class).annotatedWith(qualifier)
                .toProvider(() -> new VaultKvClient(session.get(), kvConfig)).in(SINGLETON);
        privateBinder.expose(VaultKvClient.class).annotatedWith(qualifier);
    }
}
