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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.airlift.configuration.ConfigurationFactory;
import io.airlift.configuration.TomlConfiguration;
import io.airlift.configuration.secrets.env.EnvironmentVariableSecretsPlugin;
import io.airlift.log.Logger;
import io.airlift.spi.secrets.SecretProvider;
import io.airlift.spi.secrets.SecretProviderFactory;
import io.airlift.spi.secrets.SecretsPlugin;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkState;
import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.base.Verify.verify;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.Streams.stream;
import static io.airlift.configuration.ConfigurationUtils.replaceEnvironmentVariables;
import static java.nio.file.Files.newDirectoryStream;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;

public final class SecretsPluginManager
        implements AutoCloseable
{
    private static final ImmutableList<String> SPI_PACKAGES = ImmutableList.<String>builder()
            .add("io.airlift.spi.secrets")
            .build();

    private static final Logger log = Logger.get(SecretsPluginManager.class);

    private static final String SECRETS_PROVIDER_NAME_PROPERTY = "secrets-provider.name";

    private static final Pattern SECRETS_PROVIDER_NAME_PATTERN = Pattern.compile("[a-z][a-z0-9_-]*");

    private final Map<String, SecretProviderFactory> secretsProviderFactories = new ConcurrentHashMap<>();
    private final AtomicReference<Map<String, SecretProvider>> secretsProviders = new AtomicReference<>(ImmutableMap.of());
    private final File installedSecretPluginsDir;
    private final TomlConfiguration tomlConfiguration;
    private final List<SecretProvider> managedProviders = new ArrayList<>();
    private final List<SecretsPluginClassLoader> pluginClassLoaders = new ArrayList<>();
    private boolean pluginsInstalled;
    private boolean loadStarted;
    private boolean closed;

    public SecretsPluginManager(TomlConfiguration tomlConfiguration)
    {
        this.tomlConfiguration = requireNonNull(tomlConfiguration, "tomlConfiguration is null");
        try (ConfigurationFactory configurationFactory = new ConfigurationFactory(tomlConfiguration.getParentConfiguration())) {
            SecretsPluginConfig config = configurationFactory.build(SecretsPluginConfig.class);
            this.installedSecretPluginsDir = config.getSecretsPluginsDir();
        }
    }

    public synchronized void installPlugins()
    {
        checkState(!closed, "Secrets plugin manager is closed");
        checkState(!pluginsInstalled && !loadStarted, "Secrets plugins already installed or loaded");
        pluginsInstalled = true;
        try {
            installSecretsPlugin(new EnvironmentVariableSecretsPlugin());

            listFiles(installedSecretPluginsDir).stream()
                    .filter(File::isDirectory)
                    .forEach(file -> loadConfigurationResolvers(file.getAbsolutePath(), () -> createClassLoader(file.getName(), buildClassPath(file))));
        }
        catch (RuntimeException | Error failure) {
            closeAfterFailure();
            throw failure;
        }
    }

    @VisibleForTesting
    synchronized void installSecretsPlugin(SecretsPlugin secretsPlugin)
    {
        checkState(!closed, "Secrets plugin manager is closed");
        checkState(!loadStarted, "Secrets providers already loaded");
        secretsPlugin.getSecretProviderFactories()
                .forEach(this::addSecretProviderFactory);
    }

    private void addSecretProviderFactory(SecretProviderFactory secretProviderFactory)
    {
        verify(SECRETS_PROVIDER_NAME_PATTERN.matcher(secretProviderFactory.getName()).matches(), "Secret provider name '%s' doesn't match pattern '%s'", secretProviderFactory.getName(), SECRETS_PROVIDER_NAME_PATTERN);
        secretsProviderFactories.put(
                secretProviderFactory.getName(),
                secretProviderFactory);
    }

    public synchronized void load()
    {
        checkState(!closed, "Secrets plugin manager is closed");
        checkState(!loadStarted, "Secrets providers already loaded");
        loadStarted = true;
        ImmutableMap.Builder<String, SecretProvider> builder = ImmutableMap.builder();

        try {
            for (String namespace : tomlConfiguration.getNamespaces()) {
                Map<String, String> properties = new HashMap<>(tomlConfiguration.getNamespaceConfiguration(namespace));
                properties = replaceEnvironmentVariables(properties);
                String name = properties.remove(SECRETS_PROVIDER_NAME_PROPERTY);
                checkState(!isNullOrEmpty(name), "Configuration resolver configuration '%s' does not contain '%s'", namespace, SECRETS_PROVIDER_NAME_PROPERTY);
                SecretProvider provider = loadConfigProvider(name, properties);
                managedProviders.add(provider);
                builder.put(namespace, provider);
            }
            this.secretsProviders.set(builder.buildOrThrow());
        }
        catch (RuntimeException | Error failure) {
            closeAfterFailure();
            throw failure;
        }
    }

    public synchronized SecretsResolver getSecretsResolver()
    {
        checkState(!closed, "Secrets plugin manager is closed");
        return new SecretsResolver(secretsProviders.get());
    }

    @VisibleForTesting
    synchronized void loadConfigurationResolvers(String plugin, Supplier<SecretsPluginClassLoader> createClassLoader)
    {
        checkState(!closed, "Secrets plugin manager is closed");
        checkState(!loadStarted, "Secrets providers already loaded");
        log.info("-- Loading plugin %s --", plugin);

        SecretsPluginClassLoader pluginClassLoader = createClassLoader.get();
        pluginClassLoaders.add(pluginClassLoader);

        log.debug("Classpath for plugin:");
        for (URL url : pluginClassLoader.getURLs()) {
            log.debug("    %s", url.getPath());
        }

        try (ThreadContextClassLoader ignored = new ThreadContextClassLoader(pluginClassLoader)) {
            loadConfigurationPlugin(pluginClassLoader);
        }
        catch (RuntimeException | Error failure) {
            closeAfterFailure();
            throw failure;
        }

        log.info("-- Finished loading plugin %s --", plugin);
    }

    private void loadConfigurationPlugin(SecretsPluginClassLoader pluginClassLoader)
    {
        ServiceLoader<SecretsPlugin> serviceLoader = ServiceLoader.load(SecretsPlugin.class, pluginClassLoader);
        List<SecretsPlugin> plugins = ImmutableList.copyOf(serviceLoader);
        checkState(!plugins.isEmpty(), "No service providers of type %s in the classpath: %s", SecretsPlugin.class.getName(), asList(pluginClassLoader.getURLs()));

        for (SecretsPlugin plugin : plugins) {
            log.info("Installing %s", plugin.getClass().getName());
            installSecretsPlugin(plugin);
        }
    }

    private SecretProvider loadConfigProvider(String configProviderName, Map<String, String> properties)
    {
        log.info("-- Loading secret provider --");

        SecretProviderFactory factory = secretsProviderFactories.get(configProviderName);
        checkState(factory != null, "Secret provider '%s' is not registered", configProviderName);

        SecretProvider secretProvider;
        try (ThreadContextClassLoader ignored = new ThreadContextClassLoader(factory.getClass().getClassLoader())) {
            secretProvider = factory.createSecretProvider(ImmutableMap.copyOf(properties));
        }

        log.info("-- Loaded secret provider %s --", configProviderName);
        return new ClassLoaderSafeSecretProvider(requireNonNull(secretProvider, "secretProvider is null"), factory.getClass().getClassLoader());
    }

    @Override
    public synchronized void close()
    {
        if (closed) {
            return;
        }
        closed = true;
        secretsProviders.set(ImmutableMap.of());
        boolean failed = false;
        for (SecretProvider provider : managedProviders.reversed()) {
            try {
                provider.close();
            }
            catch (Throwable ignored) {
                // Provider failures may contain secret values, including in causes or suppressed exceptions.
                failed = true;
            }
        }
        managedProviders.clear();
        secretsProviderFactories.clear();
        for (SecretsPluginClassLoader classLoader : pluginClassLoaders.reversed()) {
            try {
                classLoader.close();
            }
            catch (Throwable ignored) {
                failed = true;
            }
        }
        pluginClassLoaders.clear();
        if (failed) {
            throw new IllegalStateException("Unable to close secrets plugins");
        }
    }

    private void closeAfterFailure()
    {
        try {
            close();
        }
        catch (RuntimeException ignored) {
            // Preserve the original failure without attaching sensitive cleanup exceptions.
        }
    }

    private static final class ClassLoaderSafeSecretProvider
            implements SecretProvider
    {
        private final SecretProvider delegate;
        private final ClassLoader classLoader;
        private final AtomicBoolean closed = new AtomicBoolean();

        private ClassLoaderSafeSecretProvider(SecretProvider delegate, ClassLoader classLoader)
        {
            this.delegate = delegate;
            this.classLoader = classLoader;
        }

        @Override
        public String resolveSecretValue(String key)
        {
            checkState(!closed.get(), "Secret provider is closed");
            try (ThreadContextClassLoader ignored = new ThreadContextClassLoader(classLoader)) {
                return delegate.resolveSecretValue(key);
            }
        }

        @Override
        public void close()
                throws Exception
        {
            if (closed.compareAndSet(false, true)) {
                try (ThreadContextClassLoader ignored = new ThreadContextClassLoader(classLoader)) {
                    delegate.close();
                }
            }
        }
    }

    private static List<URL> buildClassPath(File path)
    {
        return listFiles(path).stream()
                .map(SecretsPluginManager::fileToUrl)
                .collect(toImmutableList());
    }

    private static SecretsPluginClassLoader createClassLoader(String pluginName, List<URL> urls)
    {
        ClassLoader parent = SecretsPluginManager.class.getClassLoader();
        return new SecretsPluginClassLoader(pluginName, urls, parent, SPI_PACKAGES);
    }

    private static List<File> listFiles(File path)
    {
        try {
            try (DirectoryStream<Path> directoryStream = newDirectoryStream(path.toPath())) {
                return stream(directoryStream)
                        .map(Path::toFile)
                        .sorted()
                        .collect(toImmutableList());
            }
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static URL fileToUrl(File file)
    {
        try {
            return file.toURI().toURL();
        }
        catch (MalformedURLException e) {
            throw new UncheckedIOException(e);
        }
    }
}
