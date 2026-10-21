/*
 * Copyright 2010 Proofpoint, Inc.
 *
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
package io.airlift.bootstrap;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableList.Builder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedMap;
import com.google.inject.Binder;
import com.google.inject.Binding;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import com.google.inject.Stage;
import com.google.inject.spi.Element;
import com.google.inject.spi.Elements;
import com.google.inject.spi.Message;
import io.airlift.configuration.ConfigPropertyMetadata;
import io.airlift.configuration.ConfigurationAwareModule;
import io.airlift.configuration.ConfigurationFactory;
import io.airlift.configuration.ConfigurationInspector;
import io.airlift.configuration.ConfigurationInspector.ConfigAttribute;
import io.airlift.configuration.ConfigurationInspector.ConfigRecord;
import io.airlift.configuration.ConfigurationModule;
import io.airlift.configuration.WarningsMonitor;
import io.airlift.configuration.secrets.SecretsPluginManager;
import io.airlift.configuration.secrets.SecretsResolver;
import io.airlift.configuration.secrets.env.EnvironmentVariableSecretProvider;
import io.airlift.log.Logger;
import io.airlift.log.Logging;
import io.airlift.log.LoggingConfiguration;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static io.airlift.bootstrap.FuzzyMatcher.findSimilar;
import static io.airlift.configuration.ConfigurationLoader.getSystemProperties;
import static io.airlift.configuration.ConfigurationLoader.loadPropertiesFrom;
import static io.airlift.configuration.TomlConfiguration.createTomlConfiguration;
import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

/**
 * Entry point for an application built using the platform codebase.
 * <p>
 * This class will:
 * <ul>
 * <li>load, validate and bind configurations</li>
 * <li>initialize logging</li>
 * <li>set up bootstrap management</li>
 * <li>create an Guice injector</li>
 * </ul>
 */
public class Bootstrap
        implements AutoCloseable
{
    private final String name;
    private final Logger log;

    private enum State
    {
        UNINITIALIZED, CONFIGURED, INITIALIZED, CLOSED
    }

    private final List<Module> modules;
    private Module configuredModules;

    private Map<String, String> requiredConfigurationProperties;
    private Map<String, String> optionalConfigurationProperties;
    private final Set<String> requiredRawProperties = new HashSet<>();
    private final Set<String> optionalRawProperties = new HashSet<>();
    private boolean shutdownHook = true;
    private boolean initializeLogging = true;
    private boolean envInterpolation = true;
    private boolean useSystemProperties = true;
    private boolean quiet = parseBoolean(System.getProperty("airlift.quiet"));
    private boolean loadSecretsPlugins;
    private boolean skipErrorReporting;

    private State state = State.UNINITIALIZED;
    private ConfigurationFactory configurationFactory;
    private SecretsResolver secretsResolver;
    private LifeCycleManager lifeCycleManager;

    public Bootstrap(String name, Module... modules)
    {
        this(name, ImmutableList.copyOf(modules));
    }

    public Bootstrap(Iterable<? extends Module> modules)
    {
        this("Bootstrap", modules);
    }

    public Bootstrap(Module... modules)
    {
        this(ImmutableList.copyOf(modules));
    }

    public Bootstrap(String name, Iterable<? extends Module> modules)
    {
        this.name = requireNonNull(name, "name is null");
        this.modules = ImmutableList.copyOf(modules);
        this.log = Logger.get(name);
    }

    /** Supplies a literal value, without secret or environment interpolation. */
    public Bootstrap setRequiredConfigurationProperty(String key, String value)
    {
        return setRequiredConfigurationProperties(Map.of(key, value));
    }

    /** Supplies literal values, without secret or environment interpolation. */
    public Bootstrap setRequiredConfigurationProperties(Map<String, String> properties)
    {
        return setRequiredProperties(properties, false);
    }

    public Bootstrap setRequiredRawConfigurationProperty(String key, String value)
    {
        return setRequiredRawConfigurationProperties(Map.of(key, value));
    }

    /** Supplies raw values whose surviving references will be resolved once. */
    public Bootstrap setRequiredRawConfigurationProperties(Map<String, String> properties)
    {
        return setRequiredProperties(properties, true);
    }

    private Bootstrap setRequiredProperties(Map<String, String> properties, boolean raw)
    {
        checkState(state == State.UNINITIALIZED, "Already configured");
        if (requiredConfigurationProperties == null) {
            requiredConfigurationProperties = new TreeMap<>();
        }
        requiredConfigurationProperties.putAll(properties);
        updateRawProperties(requiredRawProperties, properties.keySet(), raw);
        return this;
    }

    /** Supplies a literal value, without secret or environment interpolation. */
    public Bootstrap setOptionalConfigurationProperty(String key, String value)
    {
        return setOptionalConfigurationProperties(Map.of(key, value));
    }

    /** Supplies literal values, without secret or environment interpolation. */
    public Bootstrap setOptionalConfigurationProperties(Map<String, String> properties)
    {
        return setOptionalProperties(properties, false);
    }

    public Bootstrap setOptionalRawConfigurationProperty(String key, String value)
    {
        return setOptionalRawConfigurationProperties(Map.of(key, value));
    }

    /** Supplies raw values whose surviving references will be resolved once. */
    public Bootstrap setOptionalRawConfigurationProperties(Map<String, String> properties)
    {
        return setOptionalProperties(properties, true);
    }

    private Bootstrap setOptionalProperties(Map<String, String> properties, boolean raw)
    {
        checkState(state == State.UNINITIALIZED, "Already configured");
        if (optionalConfigurationProperties == null) {
            optionalConfigurationProperties = new TreeMap<>();
        }
        optionalConfigurationProperties.putAll(properties);
        updateRawProperties(optionalRawProperties, properties.keySet(), raw);
        return this;
    }

    private static void updateRawProperties(Set<String> rawProperties, Set<String> keys, boolean raw)
    {
        if (raw) {
            rawProperties.addAll(keys);
        }
        else {
            rawProperties.removeAll(keys);
        }
    }

    /** Disables the JVM hook for a child runtime whose owner calls close(). */
    public Bootstrap withShutdownHook(boolean enabled)
    {
        checkState(state == State.UNINITIALIZED, "Already configured");
        shutdownHook = enabled;
        return this;
    }

    public Bootstrap doNotInitializeLogging()
    {
        return withInitializeLogging(false);
    }

    public Bootstrap disableEnvInterpolation()
    {
        return withEnvInterpolation(false);
    }

    public Bootstrap disableSystemProperties()
    {
        return withUseSystemProperties(false);
    }

    public Bootstrap quiet()
    {
        return withQuiet(true);
    }

    public Bootstrap loadSecretsPlugins()
    {
        return withLoadSecretsPlugins(true);
    }

    public Bootstrap skipErrorReporting()
    {
        return withSkipErrorReporting(true);
    }

    public Bootstrap withInitializeLogging(boolean initializeLogging)
    {
        this.initializeLogging = initializeLogging;
        return this;
    }

    public Bootstrap withQuiet(boolean quiet)
    {
        this.quiet = quiet;
        return this;
    }

    public Bootstrap withLoadSecretsPlugins(boolean load)
    {
        this.loadSecretsPlugins = load;
        return this;
    }

    public Bootstrap withSkipErrorReporting(boolean skip)
    {
        this.skipErrorReporting = skip;
        return this;
    }

    public Bootstrap withEnvInterpolation(boolean interpolate)
    {
        this.envInterpolation = interpolate;
        return this;
    }

    public Bootstrap withUseSystemProperties(boolean useSystemProperties)
    {
        this.useSystemProperties = useSystemProperties;
        return this;
    }

    /**
     * Validate configuration and return used properties.
     */
    public Set<ConfigPropertyMetadata> configure()
    {
        checkState(state == State.UNINITIALIZED, "Already configured");
        state = State.CONFIGURED;
        lifeCycleManager = new LifeCycleManager(name, List.of(), null, shutdownHook);
        try {
            return configureInternal();
        }
        catch (RuntimeException | Error failure) {
            closeAfterFailure(failure);
            throw failure;
        }
    }

    private Set<ConfigPropertyMetadata> configureInternal()
    {
        Logging logging = null;
        if (initializeLogging) {
            logging = Logging.initialize();
        }

        this.secretsResolver = envInterpolation ?
                new SecretsResolver(ImmutableMap.of("env", new EnvironmentVariableSecretProvider())) :
                new SecretsResolver(ImmutableMap.of());

        if (loadSecretsPlugins) {
            log.info("Loading secrets plugins");
            String secretsConfigFile = System.getProperty("secretsConfig");
            if (secretsConfigFile != null) {
                SecretsPluginManager secretsPluginManager = new SecretsPluginManager(createTomlConfiguration(new File(secretsConfigFile)));
                // Registered first, so consumers and their configuration close before providers.
                lifeCycleManager.addCloseable(secretsPluginManager, secretsPluginManager::close);
                secretsPluginManager.installPlugins();
                secretsPluginManager.load();
                this.secretsResolver = secretsPluginManager.getSecretsResolver();
            }
        }

        Map<String, String> requiredProperties;
        Set<String> requiredRaw = requiredRawProperties;
        if (requiredConfigurationProperties == null) {
            // initialize configuration
            log.info("Loading configuration");

            requiredProperties = Collections.emptyMap();
            String configFile = System.getProperty("config");
            if (configFile != null) {
                try {
                    requiredProperties = loadPropertiesFrom(configFile);
                }
                catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
            requiredRaw = requiredProperties.keySet();
        }
        else {
            requiredProperties = requiredConfigurationProperties;
        }
        Map<String, String> unusedProperties = new TreeMap<>(requiredProperties);

        // Preserve the winning source's interpretation, including literal overrides of raw values.
        Map<String, String> properties = new HashMap<>();
        Set<String> rawProperties = new HashSet<>();
        if (optionalConfigurationProperties != null) {
            properties.putAll(optionalConfigurationProperties);
            rawProperties.addAll(optionalRawProperties);
        }
        properties.putAll(requiredProperties);
        rawProperties.removeAll(requiredProperties.keySet());
        rawProperties.addAll(requiredRaw);
        if (useSystemProperties) {
            Map<String, String> systemProperties = getSystemProperties();
            properties.putAll(systemProperties);
            rawProperties.addAll(systemProperties.keySet());
        }

        Map<String, String> rawValues = new HashMap<>();
        rawProperties.forEach(key -> rawValues.put(key, properties.remove(key)));
        List<Message> errors = new ArrayList<>();
        properties.putAll(secretsResolver.getResolvedConfiguration(rawValues, (key, error) -> {
            unusedProperties.remove(key);
            errors.add(new Message(error.getMessage()));
        }));

        List<Message> warnings = new ArrayList<>();
        configurationFactory = new ConfigurationFactory(ImmutableSortedMap.copyOf(properties), warning -> warnings.add(new Message(warning)));
        lifeCycleManager.addInstance(configurationFactory);

        Boolean quietConfig = configurationFactory.build(BootstrapConfig.class).isQuiet();

        // initialize logging
        if (logging != null) {
            log.info("Initializing logging");
            LoggingConfiguration configuration = configurationFactory.build(LoggingConfiguration.class);
            logging.configure(configuration);
        }

        // Register configuration classes defined in the modules
        errors.addAll(configurationFactory.registerConfigurationClasses(new ConfigurationAwareModule()
        {
            @Override
            public void setConfigurationFactory(ConfigurationFactory configurationFactory)
            {
                modules.stream()
                        .filter(ConfigurationAwareModule.class::isInstance)
                        .map(ConfigurationAwareModule.class::cast)
                        .forEach(module -> module.setConfigurationFactory(configurationFactory));
            }

            @Override
            public void configure(Binder binder)
            {
                // Record once: configuring a module can allocate explicitly owned resources.
                // Replay the same elements for the injector instead of allocating them again.
                AtomicReference<Error> configurationFailure = new AtomicReference<>();
                List<Element> elements = Elements.getElements(Stage.PRODUCTION, recordingBinder -> {
                    try {
                        modules.forEach(recordingBinder::install);
                    }
                    catch (Error failure) {
                        // Guice records RuntimeExceptions but propagates Errors. Retain
                        // the partial elements so explicitly owned instances are still closed.
                        configurationFailure.set(failure);
                    }
                });
                ClosingBinder.registerPendingCloseables(elements, lifeCycleManager);
                if (configurationFailure.get() != null) {
                    throw configurationFailure.get();
                }
                configuredModules = Elements.getModule(elements);
                // ConfigurationFactory inspects bindings and messages only. Provider
                // and member lookups must be applied just once, when creating the injector.
                elements.stream()
                        .filter(element -> element instanceof Binding<?> || element instanceof Message)
                        .forEach(element -> element.applyTo(binder));
            }
        }));

        // Validate configuration classes
        errors.addAll(configurationFactory.validateRegisteredConfigurationProvider());

        // at this point all config file properties should be used
        // so we can calculate the unused properties
        Set<String> usedProperties = configurationFactory.getUsedProperties().stream()
                .map(ConfigPropertyMetadata::name)
                .collect(toImmutableSet());
        unusedProperties.keySet().removeAll(usedProperties);

        for (String key : unusedProperties.keySet()) {
            errors.add(new Message(format("Configuration property '%s' was not used" + suggest(key, configurationFactory.getAllSeenProperties()), key)));
        }

        // If there are configuration errors, fail-fast to keep output clean
        if (!skipErrorReporting && !errors.isEmpty()) {
            throw new ApplicationConfigurationException(errors, warnings);
        }

        // Log effective configuration
        if (!((quietConfig == null) ? quiet : quietConfig)) {
            logConfiguration(configurationFactory);
        }

        // Log any warnings
        if (!skipErrorReporting && !warnings.isEmpty()) {
            StringBuilder message = new StringBuilder();
            message.append("Configuration warnings\n");
            message.append("==========\n\n");
            message.append("Configuration should be updated:\n\n");
            for (int index = 0; index < warnings.size(); index++) {
                message.append(format("%s) %s\n", index + 1, warnings.get(index)));
            }
            message.append("\n");
            message.append("==========");
            log.warn(message.toString());
        }

        return configurationFactory.getUsedProperties();
    }

    public Injector initialize()
    {
        checkState(state != State.INITIALIZED, "Already initialized");
        checkState(state != State.CLOSED, "Bootstrap is closed");
        if (state == State.UNINITIALIZED) {
            configure();
        }
        state = State.INITIALIZED;

        try {
            Builder<Module> moduleList = ImmutableList.builder();
            moduleList.add(new LifeCycleModule(lifeCycleManager));
            moduleList.add(new ConfigurationModule(configurationFactory));
            moduleList.add(binder -> binder.bind(WarningsMonitor.class).toInstance(log::warn));
            moduleList.add(Binder::disableCircularProxies);
            moduleList.add(Binder::requireExplicitBindings);
            moduleList.add(Binder::requireExactBindingAnnotations);
            moduleList.add(binder -> binder.bind(SecretsResolver.class).toInstance(secretsResolver));
            moduleList.add(configuredModules);

            Injector injector = Guice.createInjector(Stage.PRODUCTION, moduleList.build());
            lifeCycleManager.start();
            return injector;
        }
        catch (RuntimeException | Error failure) {
            closeAfterFailure(failure);
            throw failure;
        }
    }

    @Override
    public void close()
    {
        if (state == State.CLOSED) {
            return;
        }
        state = State.CLOSED;
        if (lifeCycleManager != null) {
            lifeCycleManager.stopWithoutFailureLogging();
        }
    }

    private void closeAfterFailure(Throwable failure)
    {
        try {
            close();
        }
        catch (RuntimeException cleanupFailure) {
            // Cleanup failures may contain provider credentials. Preserve only a safe summary.
            failure.addSuppressed(new RuntimeException("Bootstrap cleanup failed"));
        }
    }

    private void logConfiguration(ConfigurationFactory configurationFactory)
    {
        if (!log.isInfoEnabled()) {
            return;
        }

        ColumnPrinter columnPrinter = makePrinterForConfiguration(configurationFactory);
        for (String line : columnPrinter.generateOutput()) {
            log.info(line);
        }
    }

    private static ColumnPrinter makePrinterForConfiguration(ConfigurationFactory configurationFactory)
    {
        ConfigurationInspector configurationInspector = new ConfigurationInspector();

        ColumnPrinter columnPrinter = new ColumnPrinter("PROPERTY", "DEFAULT", "RUNTIME", "DESCRIPTION");

        for (ConfigRecord<?> record : configurationInspector.inspect(configurationFactory)) {
            for (ConfigAttribute attribute : record.getAttributes()) {
                columnPrinter.addValues(
                        attribute.getPropertyName(),
                        attribute.getDefaultValue(),
                        attribute.getCurrentValue(),
                        attribute.getDescription());
            }
        }
        return columnPrinter;
    }

    private static String suggest(String key, Set<String> knownProperties)
    {
        List<String> suggestions = findSimilar(key, knownProperties, 3);
        if (suggestions.isEmpty()) {
            return "";
        }

        return ". Did you mean to use " + switch (suggestions.size()) {
            case 3 -> "'" + suggestions.get(0) + "', '" + suggestions.get(1) + "' or '" + suggestions.get(2) + "'?";
            case 2 -> "'" + suggestions.get(0) + "' or '" + suggestions.get(1) + "'?";
            default -> "'" + suggestions.get(0) + "'?";
        };
    }
}
