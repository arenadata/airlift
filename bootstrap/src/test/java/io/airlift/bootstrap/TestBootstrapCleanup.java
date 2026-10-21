package io.airlift.bootstrap;

import com.google.inject.Inject;
import com.google.inject.Key;
import com.google.inject.Module;
import com.google.inject.PrivateModule;
import com.google.inject.Provider;
import com.google.inject.Scopes;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.airlift.configuration.Config;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static com.google.common.base.Throwables.getStackTraceAsString;
import static com.google.inject.name.Names.named;
import static io.airlift.bootstrap.ClosingBinder.closingBinder;
import static java.util.Arrays.stream;
import static java.util.concurrent.CompletableFuture.runAsync;
import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class TestBootstrapCleanup
{
    @Test
    void testFailedInjectorClosesProvisionedResources()
    {
        List<String> events = new ArrayList<>();
        ManagedResource resource = new ManagedResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(ManagedResource.class).toInstance(resource);
            binder.bind(String.class).toProvider(() -> {
                throw new IllegalStateException("provision failed");
            }).in(Scopes.SINGLETON);
        })) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("provision failed");
            assertThat(events).containsExactly("start", "destroy");
        }
        assertThat(events).containsExactly("start", "destroy");
    }

    @Test
    void testPartialClosingBinderSetIsCleanedUp()
    {
        AtomicInteger closes = new AtomicInteger();
        Key<AutoCloseable> first = Key.get(AutoCloseable.class, named("first"));
        Key<AutoCloseable> failure = Key.get(AutoCloseable.class, named("failure"));
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(first).toProvider(() -> closes::incrementAndGet);
            binder.bind(failure).toProvider(() -> {
                throw new IllegalStateException("second resource failed");
            });
            closingBinder(binder).registerCloseable(first);
            closingBinder(binder).registerCloseable(failure);
        })) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("second resource failed");
            assertThat(closes).hasValue(1);
        }
        assertThat(closes).hasValue(1);
    }

    @Test
    void testPostConstructFailureClosesExplicitlyOwnedResource()
    {
        AtomicInteger closes = new AtomicInteger();
        FailingResource resource = new FailingResource(closes);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(FailingResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(resource);
        })) {
            assertThatThrownBy(bootstrap::initialize).hasRootCauseMessage("start failed");
            assertThat(closes).hasValue(1);
        }
    }

    @Test
    void testLinkedBindingPostConstructFailureClosesOwnedInstances()
    {
        AtomicInteger created = new AtomicInteger();
        AtomicInteger closed = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(LinkedCounters.class).toInstance(new LinkedCounters(created, closed));
            binder.bind(OwnedResource.class).to(LinkedFailingResource.class).in(Scopes.SINGLETON);
            binder.bind(LinkedFailingResource.class).in(Scopes.SINGLETON);
            closingBinder(binder).registerCloseable(OwnedResource.class);
        })) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("PostConstruct");
            assertThat(created).hasPositiveValue();
            assertThat(closed.get()).isEqualTo(created.get());
        }
        assertThat(closed.get()).isEqualTo(created.get());
    }

    @Test
    void testAnnotationsAndClosingBinderDoNotCloseTwice()
    {
        List<String> events = new ArrayList<>();
        ManagedResource resource = new ManagedResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(ManagedResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(ManagedResource.class);
            closingBinder(binder).registerCloseable(resource);
        })) {
            var injector = bootstrap.initialize();
            assertThat(events).containsExactly("start");
            injector.getInstance(LifeCycleManager.class).stop();
            bootstrap.close();
            assertThat(events).containsExactly("start", "destroy");
        }
    }

    @Test
    void testUnboundAnnotatedClosingBinderResource()
    {
        List<String> events = new ArrayList<>();
        ManagedResource resource = new ManagedResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> closingBinder(binder).registerCloseable(resource))) {
            bootstrap.initialize();
            assertThat(events).containsExactly("start");
        }
        assertThat(events).containsExactly("start", "destroy");
    }

    @Test
    void testUnboundInstanceReceivesMemberInjectionAndLifecycle()
    {
        AtomicInteger calls = new AtomicInteger();
        MemberInjectedResource resource = new MemberInjectedResource();
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(AtomicInteger.class).toInstance(calls);
            closingBinder(binder).registerCloseable(resource);
        })) {
            bootstrap.initialize();
            assertThat(calls).hasValue(1);
        }
        assertThat(calls).hasValue(2);
    }

    @Test
    void testCleanupFailureDoesNotExposeItsCause()
    {
        String secret = "cleanup-confidential-value";
        Key<AutoCloseable> resource = Key.get(AutoCloseable.class, named("resource"));
        Key<AutoCloseable> failure = Key.get(AutoCloseable.class, named("failure"));
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(resource).toProvider(() -> () -> {
                throw new IllegalStateException(secret);
            });
            binder.bind(failure).toProvider(() -> {
                throw new IllegalStateException("provision failed");
            });
            closingBinder(binder).registerCloseable(resource);
            closingBinder(binder).registerCloseable(failure);
        })) {
            Throwable thrown = catchThrowable(bootstrap::initialize);
            assertThat(thrown).hasMessageContaining("provision failed");
            assertThat(thrown.getSuppressed()).singleElement()
                    .satisfies(cleanup -> assertThat(cleanup).hasMessage("Bootstrap cleanup failed"));
            assertThat(getStackTraceAsString(thrown)).doesNotContain(secret);
        }
    }

    @Test
    void testCallerOwnedCloseableIsNotClosed()
    {
        AtomicInteger closes = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> binder.bind(AutoCloseable.class).toInstance(closes::incrementAndGet))) {
            bootstrap.initialize();
        }
        assertThat(closes).hasValue(0);
    }

    @Test
    void testShutdownCanProvisionUnmanagedHelper()
    {
        AtomicInteger closes = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(AtomicInteger.class).toInstance(closes);
            binder.bind(CleanupHelper.class);
            binder.bind(ResourceWithLazyCleanupHelper.class).asEagerSingleton();
        })) {
            bootstrap.initialize();
            assertThat(closes).hasValue(0);
        }
        assertThat(closes).hasValue(1);
    }

    @Test
    void testIndependentLifecyclesAndReverseCleanupOrder()
    {
        List<String> events = new ArrayList<>();
        try (Bootstrap first = bootstrap(binder -> {
            closingBinder(binder).registerCloseable(() -> events.add("first"));
            closingBinder(binder).registerCloseable(() -> events.add("second"));
        });
                Bootstrap other = bootstrap(binder -> closingBinder(binder).registerCloseable(() -> events.add("other")))) {
            first.initialize();
            other.initialize();
            first.close();
            assertThat(events).containsExactly("second", "first");
        }
        assertThat(events).containsExactly("second", "first", "other");
    }

    @Test
    void testConfigureOnlyCloseAndFailureAreTerminal()
    {
        try (Bootstrap bootstrap = bootstrap()) {
            bootstrap.configure();
            bootstrap.close();
            bootstrap.close();
            assertThatThrownBy(bootstrap::initialize).hasMessage("Bootstrap is closed");
        }
        try (Bootstrap bootstrap = bootstrap().setRequiredConfigurationProperty("unknown", "literal")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
            assertThatThrownBy(bootstrap::initialize).hasMessage("Bootstrap is closed");
        }
    }

    @Test
    void testCustomCleanupRunsAlongsidePreDestroy()
    {
        List<String> events = new ArrayList<>();
        ManagedResource resource = new ManagedResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(ManagedResource.class).toInstance(resource);
            closingBinder(binder).registerResource(ManagedResource.class, _ -> events.add("custom cleanup"));
            closingBinder(binder).registerResource(ManagedResource.class, _ -> events.add("other cleanup"));
        })) {
            bootstrap.initialize();
        }
        assertThat(events).containsExactlyInAnyOrder("start", "destroy", "other cleanup", "custom cleanup");
    }

    @Test
    void testCustomCleanupClosesEveryUnscopedInstance()
    {
        AtomicInteger created = new AtomicInteger();
        AtomicInteger closed = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(DependencyResource.class).toProvider(() -> {
                created.incrementAndGet();
                return new DependencyResource(new ArrayList<>());
            });
            closingBinder(binder).registerResource(DependencyResource.class, _ -> closed.incrementAndGet());
        })) {
            var injector = bootstrap.initialize();
            injector.getInstance(DependencyResource.class);
            injector.getInstance(DependencyResource.class);
            assertThat(created.get()).isGreaterThanOrEqualTo(2);
        }
        assertThat(closed.get()).isEqualTo(created.get());
    }

    @Test
    void testExplicitInstanceClosedWhenLifecycleAnnotationsAreInvalid()
    {
        AtomicInteger closes = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> closingBinder(binder).registerCloseable(new InvalidLifecycleResource(closes)))) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("methods cannot have arguments");
            assertThat(closes).hasValue(1);
        }
        assertThat(closes).hasValue(1);
    }

    @Test
    void testExplicitAnnotatedInstanceDestroyedOnceAfterPostConstructFailure()
    {
        List<String> events = new ArrayList<>();
        try (Bootstrap bootstrap = bootstrap(binder -> closingBinder(binder).registerCloseable(new FailingManagedResource(events)))) {
            assertThatThrownBy(bootstrap::initialize).hasRootCauseMessage("annotated start failed");
            assertThat(events).containsExactly("start", "destroy");
        }
        assertThat(events).containsExactly("start", "destroy");
    }

    @Test
    void testExplicitInstanceClosedWhenConfigurationFails()
    {
        List<String> events = new ArrayList<>();
        ManagedResource resource = new ManagedResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> closingBinder(binder).registerCloseable(resource))
                .setRequiredConfigurationProperty("unknown", "value")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
            assertThat(events).containsExactly("destroy");
        }
        assertThat(events).containsExactly("destroy");
    }

    @Test
    void testExplicitInstanceClosedWhenModuleConfigurationThrows()
    {
        AtomicInteger closes = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> {
            closingBinder(binder).registerCloseable(closes::incrementAndGet);
            throw new IllegalStateException("module configuration failed");
        })) {
            assertThatThrownBy(bootstrap::configure).hasMessageContaining("module configuration failed");
            assertThat(closes).hasValue(1);
        }
        assertThat(closes).hasValue(1);
    }

    @Test
    void testExplicitInstanceClosedWhenModuleConfigurationThrowsError()
    {
        AtomicInteger closes = new AtomicInteger();
        AssertionError failure = new AssertionError("module configuration failed");
        try (Bootstrap bootstrap = bootstrap(binder -> {
            closingBinder(binder).registerCloseable(closes::incrementAndGet);
            throw failure;
        })) {
            assertThat(catchThrowable(bootstrap::configure)).isSameAs(failure);
            assertThat(closes).hasValue(1);
        }
        assertThat(closes).hasValue(1);
    }

    @Test
    void testExplicitInstanceClosesBeforeSuccessfullyInjectedDependencies()
    {
        List<String> events = new ArrayList<>();
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(DependencyResource.class).toProvider(() -> new DependencyResource(events)).in(Scopes.SINGLETON);
            closingBinder(binder).registerCloseable(DependencyResource.class);
            closingBinder(binder).registerCloseable(new AutoCloseable()
            {
                @Inject
                public void inject(DependencyResource dependency)
                {
                    events.add("injection");
                }

                @Override
                public void close()
                {
                    events.add("resource closed");
                }
            });
        })) {
            bootstrap.initialize();
        }
        assertThat(events).containsExactly("injection", "resource closed", "dependency closed");
    }

    @Test
    void testExplicitInstanceClosedWhenMemberInjectionFails()
    {
        List<String> events = new ArrayList<>();
        InjectionFailureResource resource = new InjectionFailureResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(DependencyResource.class).toProvider(() -> new DependencyResource(events)).in(Scopes.SINGLETON);
            closingBinder(binder).registerCloseable(DependencyResource.class);
            closingBinder(binder).registerCloseable(resource);
        })) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("member injection failed");
            assertThat(events).containsExactly("injection", "resource closed", "dependency closed");
        }
        assertThat(events).containsExactly("injection", "resource closed", "dependency closed");
    }

    @Test
    void testPrivateExplicitInstanceClosedWhenConfigurationFails()
    {
        AtomicInteger closes = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(new PrivateModule()
        {
            @Override
            protected void configure()
            {
                closingBinder(binder()).registerCloseable(closes::incrementAndGet);
            }
        }).setRequiredConfigurationProperty("unknown", "value")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
        }
        assertThat(closes).hasValue(1);
    }

    @Test
    void testConfigurationModuleResourcesAreCreatedOnce()
    {
        AtomicInteger created = new AtomicInteger();
        AtomicInteger closed = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(new AbstractConfigurationAwareModule()
        {
            @Override
            protected void setup(com.google.inject.Binder binder)
            {
                assertThat(binder.currentStage()).isEqualTo(com.google.inject.Stage.PRODUCTION);
                assertThat(buildConfigObject(ResourceConfig.class).getValue()).isEqualTo("configured");
                created.incrementAndGet();
                closingBinder(binder).registerCloseable(closed::incrementAndGet);
            }
        }).setRequiredConfigurationProperty("resource.value", "configured")) {
            bootstrap.configure();
            bootstrap.initialize();
            assertThat(created).hasValue(1);
            assertThat(closed).hasValue(0);
        }
        assertThat(closed).hasValue(1);
    }

    @Test
    void testConfigureOnlyClosesExplicitInstancesWithoutStartingThem()
    {
        List<String> events = new ArrayList<>();
        ManagedResource resource = new ManagedResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> closingBinder(binder).registerCloseable(resource))) {
            bootstrap.configure();
            assertThat(events).isEmpty();
        }
        assertThat(events).containsExactly("destroy");
    }

    @Test
    void testCallerOwnedInstanceIsNotClosedWhenConfigurationFails()
    {
        AtomicInteger closes = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> binder.bind(AutoCloseable.class).toInstance(closes::incrementAndGet))
                .setRequiredConfigurationProperty("unknown", "value")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
        }
        assertThat(closes).hasValue(0);
    }

    @TestFactory
    Stream<DynamicTest> testKeyBoundInstanceClosedWhenConfigurationFails()
    {
        return stream(InstanceBindingType.values()).map(bindingType -> dynamicTest(bindingType.name(), () -> {
            KeyResource resource = new KeyResource(false);
            try (Bootstrap bootstrap = bootstrap(bindingType.module(resource))
                    .setRequiredConfigurationProperty("unknown", "value")) {
                assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
                assertThat(resource.closes).hasValue(1);
                bootstrap.close();
                bootstrap.close();
            }
            assertThat(resource.closes).hasValue(1);
        }));
    }

    @TestFactory
    Stream<DynamicTest> testKeyBoundInstanceClosedWhenMemberInjectionFails()
    {
        return stream(InstanceBindingType.values()).map(bindingType -> dynamicTest(bindingType.name(), () -> {
            KeyResource resource = new KeyResource(true);
            try (Bootstrap bootstrap = bootstrap(bindingType.module(resource))) {
                assertThatThrownBy(bootstrap::initialize).hasMessageContaining("key resource injection failed");
                assertThat(resource.closes).hasValue(1);
                bootstrap.close();
                bootstrap.close();
            }
            assertThat(resource.closes).hasValue(1);
        }));
    }

    @TestFactory
    Stream<DynamicTest> testKeyBoundInstanceClosedOnceAfterSuccessfulStartup()
    {
        return stream(InstanceBindingType.values()).map(bindingType -> dynamicTest(bindingType.name(), () -> {
            KeyResource resource = new KeyResource(false);
            try (Bootstrap bootstrap = bootstrap(bindingType.module(resource))) {
                bootstrap.initialize();
                assertThat(resource.closes).hasValue(0);
                bootstrap.close();
                bootstrap.close();
            }
            assertThat(resource.closes).hasValue(1);
        }));
    }

    @Test
    void testPrivateKeyRegistrationsDoNotOwnParentOrSiblingResources()
    {
        KeyResource parent = new KeyResource(false);
        KeyResource first = new KeyResource(false);
        KeyResource second = new KeyResource(false);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(KeyResource.class).toInstance(parent);
            for (KeyResource resource : List.of(first, second)) {
                binder.install(new PrivateModule()
                {
                    @Override
                    protected void configure()
                    {
                        bind(KeyResource.class).toInstance(resource);
                        closingBinder(binder()).registerCloseable(KeyResource.class);
                    }
                });
            }
        }).setRequiredConfigurationProperty("unknown", "value")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(parent.closes).hasValue(0);
        assertThat(first.closes).hasValue(1);
        assertThat(second.closes).hasValue(1);
    }

    @Test
    void testPrivateLinkedKeyCanOwnParentInstance()
    {
        KeyResource resource = new KeyResource(false);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(KeyResource.class).toInstance(resource);
            binder.install(new PrivateModule()
            {
                @Override
                protected void configure()
                {
                    bind(OwnedResource.class).to(KeyResource.class);
                    closingBinder(binder()).registerCloseable(OwnedResource.class);
                }
            });
        }).setRequiredConfigurationProperty("unknown", "value")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(resource.closes).hasValue(1);
    }

    @Test
    void testKeyBoundInstanceClosedWhenModuleConfigurationThrows()
    {
        KeyResource resource = new KeyResource(false);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(KeyResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(KeyResource.class);
            throw new IllegalStateException("module configuration failed");
        })) {
            assertThatThrownBy(bootstrap::configure).hasMessageContaining("module configuration failed");
            assertThat(resource.closes).hasValue(1);
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(resource.closes).hasValue(1);
    }

    @Test
    void testKeyBoundInstanceClosedWhenModuleConfigurationThrowsError()
    {
        KeyResource resource = new KeyResource(false);
        AssertionError failure = new AssertionError("module configuration failed");
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(KeyResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(KeyResource.class);
            throw failure;
        })) {
            assertThat(catchThrowable(bootstrap::configure)).isSameAs(failure);
            assertThat(resource.closes).hasValue(1);
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(resource.closes).hasValue(1);
    }

    @Test
    void testCyclicKeysDoNotPreventCleanupOfOwnedInstances()
    {
        KeyResource resource = new KeyResource(false);
        Key<AutoCloseable> first = Key.get(AutoCloseable.class, named("first"));
        Key<AutoCloseable> second = Key.get(AutoCloseable.class, named("second"));
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(first).to(second);
            binder.bind(second).to(first);
            closingBinder(binder).registerCloseable(first);
            binder.bind(KeyResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(KeyResource.class);
        }).setRequiredConfigurationProperty("unknown", "value")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
            assertThat(resource.closes).hasValue(1);
        }
        assertThat(resource.closes).hasValue(1);
    }

    @Test
    void testKeyBoundInstanceClosedWhenLifecycleAnnotationsAreInvalid()
    {
        AtomicInteger closes = new AtomicInteger();
        InvalidLifecycleResource resource = new InvalidLifecycleResource(closes);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(InvalidLifecycleResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(InvalidLifecycleResource.class);
        })) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("methods cannot have arguments");
            assertThat(closes).hasValue(1);
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(closes).hasValue(1);
    }

    @Test
    void testKeyBoundInstanceClosesBeforeDependenciesWhenMemberInjectionFails()
    {
        List<String> events = new ArrayList<>();
        InjectionFailureResource resource = new InjectionFailureResource(events);
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(DependencyResource.class).toProvider(() -> new DependencyResource(events)).in(Scopes.SINGLETON);
            closingBinder(binder).registerCloseable(DependencyResource.class);
            binder.bind(InjectionFailureResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(InjectionFailureResource.class);
        })) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("member injection failed");
            assertThat(events).containsExactly("injection", "resource closed", "dependency closed");
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(events).containsExactly("injection", "resource closed", "dependency closed");
    }

    @Test
    void testKeyBoundExecutorClosedWhenConfigurationFails()
            throws Exception
    {
        AtomicReference<ExecutorService> executorReference = new AtomicReference<>();
        AtomicInteger tasks = new AtomicInteger();
        try {
            try (Bootstrap bootstrap = bootstrap(binder -> {
                ExecutorService executor = newSingleThreadExecutor();
                executorReference.set(executor);
                runAsync(tasks::incrementAndGet, executor).join();
                binder.bind(ExecutorService.class).toInstance(executor);
                closingBinder(binder).registerExecutor(ExecutorService.class);
            }).setRequiredConfigurationProperty("unknown", "value")) {
                assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
                assertThat(executorReference.get().isShutdown()).isTrue();
                bootstrap.close();
                bootstrap.close();
            }
            assertThat(executorReference.get().awaitTermination(10, SECONDS)).isTrue();
            assertThat(tasks).hasValue(1);
        }
        finally {
            ExecutorService executor = executorReference.get();
            if (executor != null) {
                executor.shutdownNow();
                assertThat(executor.awaitTermination(10, SECONDS)).isTrue();
            }
        }
    }

    @Test
    void testCustomCleanupRunsWhenKeyBoundInstanceConfigurationFails()
    {
        KeyResource resource = new KeyResource(false);
        AtomicInteger callbacks = new AtomicInteger();
        Key<KeyResource> key = Key.get(KeyResource.class, named("resource"));
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(key).toInstance(resource);
            closingBinder(binder).registerResource(key, _ -> callbacks.incrementAndGet());
        }).setRequiredConfigurationProperty("unknown", "value")) {
            assertThatThrownBy(bootstrap::configure).isInstanceOf(ApplicationConfigurationException.class);
            assertThat(callbacks).hasValue(1);
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(callbacks).hasValue(1);
        assertThat(resource.closes).hasValue(0);
    }

    @Test
    void testCustomCleanupAndStandardCloseRunOnceWhenMemberInjectionFails()
    {
        KeyResource resource = new KeyResource(true);
        AtomicInteger callbacks = new AtomicInteger();
        try (Bootstrap bootstrap = bootstrap(binder -> {
            binder.bind(KeyResource.class).toInstance(resource);
            closingBinder(binder).registerCloseable(KeyResource.class);
            closingBinder(binder).registerResource(KeyResource.class, _ -> callbacks.incrementAndGet());
        })) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("key resource injection failed");
            assertThat(callbacks).hasValue(1);
            assertThat(resource.closes).hasValue(1);
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(callbacks).hasValue(1);
        assertThat(resource.closes).hasValue(1);
    }

    @Test
    void testCallerOwnedInstanceIsNotClosedWhenMemberInjectionFails()
    {
        KeyResource resource = new KeyResource(true);
        try (Bootstrap bootstrap = bootstrap(binder -> binder.bind(KeyResource.class).toInstance(resource))) {
            assertThatThrownBy(bootstrap::initialize).hasMessageContaining("key resource injection failed");
            bootstrap.close();
            bootstrap.close();
        }
        assertThat(resource.closes).hasValue(0);
    }

    private enum InstanceBindingType
    {
        CLASS,
        QUALIFIED_KEY,
        LINKED_KEY,
        PRIVATE_KEY,
        EXPOSED_KEY;

        Module module(KeyResource resource)
        {
            return switch (this) {
                case CLASS -> binder -> {
                    binder.bind(KeyResource.class).toInstance(resource);
                    closingBinder(binder).registerCloseable(KeyResource.class);
                };
                case QUALIFIED_KEY -> binder -> {
                    Key<KeyResource> key = Key.get(KeyResource.class, named("resource"));
                    binder.bind(key).toInstance(resource);
                    closingBinder(binder).registerCloseable(key);
                };
                case LINKED_KEY -> binder -> {
                    binder.bind(KeyResource.class).toInstance(resource);
                    binder.bind(OwnedResource.class).to(KeyResource.class);
                    closingBinder(binder).registerCloseable(OwnedResource.class);
                };
                case PRIVATE_KEY -> new PrivateModule()
                {
                    @Override
                    protected void configure()
                    {
                        bind(KeyResource.class).toInstance(resource);
                        closingBinder(binder()).registerCloseable(KeyResource.class);
                    }
                };
                case EXPOSED_KEY -> binder -> {
                    binder.install(new PrivateModule()
                    {
                        @Override
                        protected void configure()
                        {
                            bind(KeyResource.class).toInstance(resource);
                            expose(KeyResource.class);
                        }
                    });
                    closingBinder(binder).registerCloseable(KeyResource.class);
                };
            };
        }
    }

    public static class KeyResource
            implements OwnedResource
    {
        private final AtomicInteger closes = new AtomicInteger();
        private final boolean failInjection;

        public KeyResource(boolean failInjection)
        {
            this.failInjection = failInjection;
        }

        @Inject
        public void inject()
        {
            if (failInjection) {
                throw new IllegalStateException("key resource injection failed");
            }
        }

        @Override
        public void close()
        {
            closes.incrementAndGet();
        }
    }

    private static Bootstrap bootstrap(Module... modules)
    {
        return new Bootstrap(modules)
                .doNotInitializeLogging()
                .disableSystemProperties()
                .setRequiredConfigurationProperties(Map.of())
                .withShutdownHook(false)
                .quiet();
    }

    public static class InvalidLifecycleResource
            implements AutoCloseable
    {
        private final AtomicInteger closes;

        public InvalidLifecycleResource(AtomicInteger closes)
        {
            this.closes = closes;
        }

        @PostConstruct
        public void start(String invalidParameter) {}

        @Override
        public void close()
        {
            closes.incrementAndGet();
        }
    }

    public static class FailingManagedResource
            implements AutoCloseable
    {
        private final List<String> events;

        public FailingManagedResource(List<String> events)
        {
            this.events = events;
        }

        @PostConstruct
        public void start()
        {
            events.add("start");
            throw new IllegalStateException("annotated start failed");
        }

        @Override
        @PreDestroy
        public void close()
        {
            events.add("destroy");
        }
    }

    public static class ResourceConfig
    {
        private String value;

        public String getValue()
        {
            return value;
        }

        @Config("resource.value")
        public ResourceConfig setValue(String value)
        {
            this.value = value;
            return this;
        }
    }

    public static class InjectionFailureResource
            implements AutoCloseable
    {
        private final List<String> events;

        public InjectionFailureResource(List<String> events)
        {
            this.events = events;
        }

        @Inject
        public void inject(DependencyResource dependency)
        {
            events.add("injection");
            throw new IllegalStateException("member injection failed");
        }

        @PostConstruct
        public void start()
        {
            events.add("start");
        }

        @Override
        @PreDestroy
        public void close()
        {
            events.add("resource closed");
        }
    }

    private record DependencyResource(List<String> events)
            implements AutoCloseable
    {
        @Override
        public void close()
        {
            events.add("dependency closed");
        }
    }

    private record LinkedCounters(AtomicInteger created, AtomicInteger closed) {}

    private interface OwnedResource
            extends AutoCloseable {}

    public static class CleanupHelper
    {
        private final AtomicInteger closes;

        @Inject
        public CleanupHelper(AtomicInteger closes)
        {
            this.closes = closes;
        }

        public void closeResource()
        {
            closes.incrementAndGet();
        }
    }

    public static class ResourceWithLazyCleanupHelper
    {
        private final Provider<CleanupHelper> helper;

        @Inject
        public ResourceWithLazyCleanupHelper(Provider<CleanupHelper> helper)
        {
            this.helper = helper;
        }

        @PreDestroy
        public void close()
        {
            helper.get().closeResource();
        }
    }

    public static class LinkedFailingResource
            implements OwnedResource
    {
        private final LinkedCounters counters;

        @Inject
        public LinkedFailingResource(LinkedCounters counters)
        {
            this.counters = counters;
            counters.created().incrementAndGet();
        }

        @PostConstruct
        public void start()
        {
            throw new IllegalStateException("linked start failed");
        }

        @Override
        public void close()
        {
            counters.closed().incrementAndGet();
        }
    }

    public static class ManagedResource
            implements AutoCloseable
    {
        private final List<String> events;

        public ManagedResource(List<String> events)
        {
            this.events = events;
        }

        @PostConstruct
        public void start()
        {
            events.add("start");
        }

        @Override
        @PreDestroy
        public void close()
        {
            events.add("destroy");
        }
    }

    public static class MemberInjectedResource
            implements AutoCloseable
    {
        @Inject
        private AtomicInteger calls;

        @PostConstruct
        public void start()
        {
            calls.incrementAndGet();
        }

        @Override
        public void close()
        {
            calls.incrementAndGet();
        }
    }

    public static class FailingResource
            implements AutoCloseable
    {
        private final AtomicInteger closes;

        public FailingResource(AtomicInteger closes)
        {
            this.closes = closes;
        }

        @PostConstruct
        public void start()
        {
            throw new IllegalStateException("start failed");
        }

        @Override
        public void close()
        {
            closes.incrementAndGet();
        }
    }
}
