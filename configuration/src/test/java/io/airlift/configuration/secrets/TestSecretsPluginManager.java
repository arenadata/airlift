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
package io.airlift.configuration.secrets;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.airlift.configuration.TomlConfiguration;
import io.airlift.configuration.secrets.env.EnvironmentVariableSecretsPlugin;
import io.airlift.spi.secrets.SecretProvider;
import io.airlift.spi.secrets.SecretProviderFactory;
import io.airlift.spi.secrets.SecretsPlugin;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.tomlj.Toml;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class TestSecretsPluginManager
{
    @TempDir
    Path pluginDirectory;

    @Test
    void testInvalidSecretProviderName()
            throws Exception
    {
        assertInvalidSecretProviderFactory("$invalid");
        assertInvalidSecretProviderFactory("1invalid");
        assertInvalidSecretProviderFactory("invAlid");
    }

    @Test
    void testLoadingWithUnknownConfigurationResolverName()
            throws Exception
    {
        Path configPluginDirectory = Files.createTempDirectory("config-plugins");
        SecretsPluginManager configurationPluginManager = new SecretsPluginManager(
                new TomlConfiguration(Toml.parse(
                        """
                        secrets-plugins-dir="%s"

                        [resolver-1]
                        secrets-provider.name="unknown"
                        """.formatted(configPluginDirectory.toAbsolutePath()))));

        assertThatThrownBy(configurationPluginManager::load)
                .hasMessageContaining("Secret provider 'unknown' is not registered");
    }

    @Test
    void testConfigurationResolutionWithoutEnvironmentVariableResolverConfigured()
            throws Exception
    {
        Path configPluginDirectory = Files.createTempDirectory("config-plugins");
        SecretsPluginManager configurationPluginManager = new SecretsPluginManager(
                new TomlConfiguration(Toml.parse(
                        """
                        secrets-plugins-dir="%s"
                        """.formatted(configPluginDirectory.toAbsolutePath()))));

        configurationPluginManager.installPlugins();
        configurationPluginManager.load();

        assertThatThrownBy(() -> configurationPluginManager.getSecretsResolver().getResolvedConfiguration(ImmutableMap.of("key", "${ENV:test}")))
                .hasMessageContaining("No secret provider for key 'env'");
    }

    @Test
    void testFailedNamespaceClosesEarlierProviders()
    {
        List<String> events = new ArrayList<>();
        AtomicInteger creations = new AtomicInteger();
        try (SecretsPluginManager manager = manager("first", "second")) {
            installFactory(manager, _ -> {
                if (creations.incrementAndGet() == 2) {
                    throw new IllegalArgumentException("Invalid second namespace");
                }
                return provider("first", events, true);
            });

            assertThatThrownBy(manager::load)
                    .hasMessage("Invalid second namespace")
                    .hasNoCause()
                    .hasNoSuppressedExceptions();
            assertThat(events).containsExactly("close-first");
            assertThatThrownBy(manager::load).hasMessage("Secrets plugin manager is closed");
            assertThatThrownBy(manager::getSecretsResolver).hasMessage("Secrets plugin manager is closed");
        }
        assertThat(events).containsExactly("close-first");
    }

    @Test
    void testProvidersCloseOnceInReverseCreationOrder()
    {
        List<String> events = new ArrayList<>();
        List<String> created = new ArrayList<>();
        SecretsResolver resolver;
        try (SecretsPluginManager manager = manager("first", "second")) {
            installFactory(manager, config -> {
                String name = config.get("name");
                created.add("close-" + name);
                return provider(name, events, false);
            });
            manager.load();
            resolver = manager.getSecretsResolver();
            assertThat(resolver.resolveSecret("first", "key")).isEqualTo("first");
            manager.close();
            manager.close();
            assertThat(events).containsExactlyElementsOf(created.reversed());
        }
        assertThat(events).containsExactlyElementsOf(created.reversed());
        assertThatThrownBy(() -> resolver.resolveSecret("first", "key")).hasMessage("Secret provider is closed");
    }

    @Test
    void testLoadIsOneShotWithoutReplacingProviders()
    {
        List<String> events = new ArrayList<>();
        try (SecretsPluginManager manager = manager("first")) {
            installFactory(manager, _ -> provider("first", events, false));
            manager.load();
            assertThatThrownBy(manager::load).hasMessage("Secrets providers already loaded");
            assertThatThrownBy(manager::installPlugins).hasMessage("Secrets plugins already installed or loaded");
            assertThat(manager.getSecretsResolver().resolveSecret("first", "key")).isEqualTo("first");
            assertThat(events).isEmpty();
        }
        assertThat(events).containsExactly("close-first");
    }

    @Test
    void testCleanupFailuresDoNotExposeSecretsOrSkipOtherProviders()
    {
        List<String> events = new ArrayList<>();
        List<String> created = new ArrayList<>();
        try (SecretsPluginManager manager = manager("first", "second")) {
            installFactory(manager, config -> {
                String name = config.get("name");
                created.add("close-" + name);
                return provider(name, events, true);
            });
            manager.load();
            assertThatThrownBy(manager::close)
                    .hasMessage("Unable to close secrets plugins")
                    .hasNoCause()
                    .hasNoSuppressedExceptions()
                    .satisfies(failure -> {
                        StringWriter stack = new StringWriter();
                        failure.printStackTrace(new PrintWriter(stack));
                        assertThat(stack.toString()).doesNotContain("secret-value", "secret-cause", "secret-suppressed");
                    });
        }
        assertThat(events).containsExactlyElementsOf(created.reversed());
    }

    @Test
    void testProviderCallsUseFactoryClassLoaderAndRestoreCaller()
            throws Exception
    {
        ClassLoader caller = Thread.currentThread().getContextClassLoader();
        List<String> events = new ArrayList<>();
        try (URLClassLoader pluginLoader = new URLClassLoader(new URL[0], getClass().getClassLoader());
                SecretsPluginManager manager = manager("first")) {
            SecretProviderFactory factory = (SecretProviderFactory) Proxy.newProxyInstance(
                    pluginLoader,
                    new Class<?>[] {SecretProviderFactory.class},
                    (_, method, _) -> switch (method.getName()) {
                        case "getName" -> "test";
                        case "createSecretProvider" -> {
                            assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(pluginLoader);
                            events.add("create");
                            yield new SecretProvider()
                            {
                                @Override
                                public String resolveSecretValue(String key)
                                {
                                    assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(pluginLoader);
                                    events.add("resolve");
                                    throw new IllegalStateException("Resolution failed");
                                }

                                @Override
                                public void close()
                                {
                                    assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(pluginLoader);
                                    events.add("close");
                                    throw new IllegalStateException("secret-value");
                                }
                            };
                        }
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
            manager.installSecretsPlugin(() -> List.of(factory));
            manager.load();
            assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(caller);
            assertThatThrownBy(() -> manager.getSecretsResolver().resolveSecret("first", "key"))
                    .hasMessage("Resolution failed");
            assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(caller);
            assertThatThrownBy(manager::close).hasMessage("Unable to close secrets plugins");
            assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(caller);
        }
        assertThat(events).containsExactly("create", "resolve", "close");
    }

    @Test
    void testProvidersCloseBeforePluginClassLoaders()
            throws Exception
    {
        List<String> events = new ArrayList<>();
        try (SecretsPluginManager manager = manager("first")) {
            manager.loadConfigurationResolvers("one", () -> classLoader("one", events, true));
            manager.loadConfigurationResolvers("two", () -> classLoader("two", events, true));
            installFactory(manager, _ -> provider("first", events, false));
            manager.load();
        }
        assertThat(events).containsExactly("close-first", "loader-two", "loader-one");
    }

    @Test
    void testFailedInstallationClosesAllClassLoaders()
    {
        List<String> events = new ArrayList<>();
        ClassLoader caller = Thread.currentThread().getContextClassLoader();
        try (SecretsPluginManager manager = manager()) {
            manager.loadConfigurationResolvers("one", () -> classLoader("one", events, true));
            assertThatThrownBy(() -> manager.loadConfigurationResolvers("two", () -> classLoader("two", events, false)))
                    .hasMessageContaining("No service providers");
            assertThat(Thread.currentThread().getContextClassLoader()).isSameAs(caller);
            assertThatThrownBy(manager::installPlugins).hasMessage("Secrets plugin manager is closed");
            assertThat(events).containsExactly("loader-two", "loader-one");
        }
        assertThat(events).containsExactly("loader-two", "loader-one");
    }

    @Test
    void testRepeatedInstallationIsRejected()
    {
        try (SecretsPluginManager manager = manager()) {
            manager.installPlugins();
            assertThatThrownBy(manager::installPlugins).hasMessage("Secrets plugins already installed or loaded");
            manager.load();
        }
    }

    private SecretsPluginManager manager(String... namespaces)
    {
        StringBuilder config = new StringBuilder("secrets-plugins-dir=\"%s\"\n".formatted(pluginDirectory));
        for (String namespace : namespaces) {
            config.append("[%s]\nsecrets-provider.name=\"test\"\nname=\"%s\"\n".formatted(namespace, namespace));
        }
        return new SecretsPluginManager(new TomlConfiguration(Toml.parse(config.toString())));
    }

    private static void installFactory(SecretsPluginManager manager, Function<Map<String, String>, SecretProvider> create)
    {
        manager.installSecretsPlugin(() -> List.of(new SecretProviderFactory()
        {
            @Override
            public String getName()
            {
                return "test";
            }

            @Override
            public SecretProvider createSecretProvider(Map<String, String> config)
            {
                return create.apply(config);
            }
        }));
    }

    private static SecretProvider provider(String name, List<String> events, boolean failClose)
    {
        return new SecretProvider()
        {
            @Override
            public String resolveSecretValue(String key)
            {
                return name;
            }

            @Override
            public void close()
            {
                events.add("close-" + name);
                if (failClose) {
                    RuntimeException failure = new RuntimeException("secret-value", new RuntimeException("secret-cause"));
                    failure.addSuppressed(new RuntimeException("secret-suppressed"));
                    throw failure;
                }
            }
        };
    }

    private SecretsPluginClassLoader classLoader(String name, List<String> events, boolean hasPlugin)
    {
        return new SecretsPluginClassLoader(name, List.of(), getClass().getClassLoader(), List.of("io.airlift.spi.secrets"))
        {
            @Override
            public Enumeration<URL> getResources(String resource)
                    throws IOException
            {
                if (hasPlugin && resource.equals("META-INF/services/" + SecretsPlugin.class.getName())) {
                    Path service = Files.writeString(pluginDirectory.resolve(name + ".service"), EnvironmentVariableSecretsPlugin.class.getName());
                    return Collections.enumeration(List.of(service.toUri().toURL()));
                }
                return Collections.emptyEnumeration();
            }

            @Override
            protected Class<?> loadClass(String className, boolean resolve)
                    throws ClassNotFoundException
            {
                if (className.equals(EnvironmentVariableSecretsPlugin.class.getName())) {
                    return EnvironmentVariableSecretsPlugin.class;
                }
                return super.loadClass(className, resolve);
            }

            @Override
            public void close()
                    throws IOException
            {
                events.add("loader-" + name);
                super.close();
            }
        };
    }

    private void assertInvalidSecretProviderFactory(String secretProviderName)
            throws Exception
    {
        Path configPluginDirectory = Files.createTempDirectory("config-plugins");
        SecretsPluginManager configurationPluginManager = new SecretsPluginManager(
                new TomlConfiguration(Toml.parse(
                        """
                        secrets-plugins-dir="%s"

                        [resolver-1]
                        secrets-provider.name="%s"
                        """.formatted(configPluginDirectory.toAbsolutePath(), secretProviderName))));

        assertThatThrownBy(() -> configurationPluginManager.installSecretsPlugin(() -> ImmutableList.of(new SecretProviderFactory()
        {
            @Override
            public String getName()
            {
                return secretProviderName;
            }

            @Override
            public SecretProvider createSecretProvider(Map<String, String> config)
            {
                return key -> key;
            }
        }))).hasMessageContaining("Secret provider name '%s' doesn't match pattern '[a-z][a-z0-9_-]*'".formatted(secretProviderName));
    }
}
