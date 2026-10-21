package io.airlift.bootstrap;

import com.google.inject.Binder;
import com.google.inject.Binding;
import com.google.inject.BindingAnnotation;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Provider;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.spi.Element;
import com.google.inject.spi.ExposedBinding;
import com.google.inject.spi.InstanceBinding;
import com.google.inject.spi.LinkedKeyBinding;
import com.google.inject.spi.PrivateElements;
import com.google.inject.spi.ProviderInstanceBinding;
import com.google.inject.spi.ProvisionListener;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.function.Consumer;

import static com.google.common.base.Verify.verifyNotNull;
import static com.google.inject.matcher.Matchers.any;
import static com.google.inject.multibindings.Multibinder.newSetBinder;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static java.util.Collections.synchronizedMap;
import static java.util.Objects.requireNonNull;

public class ClosingBinder
{
    public static ClosingBinder closingBinder(Binder binder)
    {
        return new ClosingBinder(binder);
    }

    private final Binder binder;
    private final Multibinder<Registration> registrations;
    private final Provider<LifeCycleManager> lifecycle;

    private ClosingBinder(Binder binder)
    {
        this.binder = requireNonNull(binder, "binder is null");
        registrations = newSetBinder(binder, Registration.class, ForCleanup.class);
        lifecycle = binder.getProvider(LifeCycleManager.class);
        // Force every registration to be provisioned, but never wait for the complete
        // set to exist before recording ownership of each individual resource.
        binder.bind(Cleanup.class).asEagerSingleton();
    }

    public void registerExecutor(Class<? extends ExecutorService> type)
    {
        registerExecutor(Key.get(type));
    }

    public void registerExecutor(Key<? extends ExecutorService> key)
    {
        register(key, ExecutorService::shutdownNow, false);
    }

    public void registerCloseable(Class<? extends AutoCloseable> type)
    {
        registerCloseable(Key.get(type));
    }

    public void registerCloseable(Key<? extends AutoCloseable> key)
    {
        register(key, AutoCloseable::close, true);
    }

    public <T> void registerResource(Class<T> type, Consumer<? super T> close)
    {
        registerResource(Key.get(type), close);
    }

    public <T> void registerResource(Key<T> key, Consumer<? super T> close)
    {
        requireNonNull(close, "close is null");
        register(key, close::accept, false);
    }

    private <T> void register(Key<T> key, CloseAction<? super T> close, boolean standardClose)
    {
        requireNonNull(key, "key is null");
        ResourceRegistration<T> registration = new ResourceRegistration<>(key, close, standardClose);
        // This listener runs inside LifeCycleModule's listener. Record ownership
        // before @PostConstruct, including when that method fails.
        Provider<Injector> injector = binder.getProvider(Injector.class);
        binder.bindListener(any(), new ProvisionListener()
        {
            @Override
            public <V> void onProvision(ProvisionInvocation<V> provision)
            {
                V instance = provision.provision();
                if (instance != null && isTargetBinding(injector.get(), key, provision.getBinding())) {
                    @SuppressWarnings("unchecked")
                    T resource = (T) instance;
                    registration.register(lifecycle.get(), resource);
                }
            }
        });
        registrations.addBinding().toProvider(registration);
    }

    private static boolean isTargetBinding(Injector injector, Key<?> key, Binding<?> target)
    {
        Binding<?> binding = injector.getExistingBinding(key);
        while (binding != null) {
            if (binding.equals(target)) {
                return true;
            }
            if (binding instanceof LinkedKeyBinding<?> linked) {
                binding = injector.getExistingBinding(linked.getLinkedKey());
            }
            else if (binding instanceof ExposedBinding<?> exposed) {
                injector = exposed.getPrivateElements().getInjector();
                binding = injector.getExistingBinding(binding.getKey());
            }
            else {
                return false;
            }
        }
        return false;
    }

    public void registerCloseable(AutoCloseable instance)
    {
        requireNonNull(instance, "instance is null");
        // Preserve Guice member injection and lifecycle notifications for an instance
        // which is only registered here, without otherwise binding its concrete type.
        newSetBinder(binder, AutoCloseable.class, ForCleanup.class).addBinding().toInstance(instance);
        newSetBinder(binder, InstanceRegistration.class, ForCleanup.class).addBinding().toInstance(new InstanceRegistration(instance));
        binder.bindListener(any(), new ProvisionListener()
        {
            @Override
            public <T> void onProvision(ProvisionInvocation<T> provision)
            {
                T provisioned = provision.provision();
                if (provisioned == instance) {
                    lifecycle.get().addCloseable(instance, instance);
                }
            }
        });
        registrations.addBinding().toProvider(() -> {
            lifecycle.get().addCloseable(instance, instance);
            return new Registration();
        });
    }

    static void registerPendingCloseables(List<Element> elements, LifeCycleManager lifecycle)
    {
        new BindingScope(null, elements).registerPendingCloseables(lifecycle);
    }

    // Resolve only explicit instance bindings, without provisioning anything or
    // flattening private scopes. Ownership must survive configuration validation
    // and member injection failures, before a resource's provision listener runs.
    private static final class BindingScope
    {
        private final BindingScope parent;
        private final List<Element> elements;
        private final Map<Key<?>, List<Binding<?>>> bindings = new HashMap<>();
        private final Map<Key<?>, List<BindingScope>> exposedBindings = new HashMap<>();
        private final Map<PrivateElements, BindingScope> privateScopes = new IdentityHashMap<>();

        private BindingScope(BindingScope parent, List<Element> elements)
        {
            this.parent = parent;
            this.elements = elements;
            for (Element element : elements) {
                if (element instanceof Binding<?> binding) {
                    bindings.computeIfAbsent(binding.getKey(), _ -> new ArrayList<>()).add(binding);
                }
                else if (element instanceof PrivateElements privateElements) {
                    BindingScope scope = new BindingScope(this, privateElements.getElements());
                    privateScopes.put(privateElements, scope);
                    for (Key<?> key : privateElements.getExposedKeys()) {
                        exposedBindings.computeIfAbsent(key, _ -> new ArrayList<>()).add(scope);
                    }
                }
            }
        }

        private void registerPendingCloseables(LifeCycleManager lifecycle)
        {
            for (Element element : elements) {
                if (element instanceof InstanceBinding<?> binding && binding.getInstance() instanceof InstanceRegistration registration) {
                    lifecycle.addPendingCloseable(registration.instance());
                }
                else if (element instanceof ProviderInstanceBinding<?> binding && binding.getUserSuppliedProvider() instanceof ResourceRegistration<?> registration) {
                    forEachInstance(registration.key, new HashSet<>(), instance -> registration.registerPending(lifecycle, instance));
                }
                else if (element instanceof PrivateElements privateElements) {
                    privateScopes.get(privateElements).registerPendingCloseables(lifecycle);
                }
            }
        }

        private void forEachInstance(Key<?> key, Set<ScopedKey> visited, Consumer<Object> consumer)
        {
            if (!visited.add(new ScopedKey(this, key))) {
                return;
            }
            List<Binding<?>> localBindings = bindings.getOrDefault(key, List.of());
            List<BindingScope> exposedScopes = exposedBindings.getOrDefault(key, List.of());
            if (localBindings.isEmpty() && exposedScopes.isEmpty() && parent != null) {
                parent.forEachInstance(key, visited, consumer);
            }
            for (Binding<?> binding : localBindings) {
                if (binding instanceof InstanceBinding<?> instanceBinding) {
                    consumer.accept(instanceBinding.getInstance());
                }
                else if (binding instanceof LinkedKeyBinding<?> linked) {
                    forEachInstance(linked.getLinkedKey(), visited, consumer);
                }
            }
            for (BindingScope scope : exposedScopes) {
                scope.forEachInstance(key, visited, consumer);
            }
        }
    }

    private record ScopedKey(BindingScope scope, Key<?> key) {}

    private record InstanceRegistration(AutoCloseable instance) {}

    @FunctionalInterface
    private interface CloseAction<T>
    {
        void close(T resource)
                throws Exception;
    }

    private static class ResourceRegistration<T>
            implements Provider<Registration>
    {
        private final Key<T> key;
        private final CloseAction<? super T> close;
        private final boolean standardClose;
        private final Map<T, Object> cleanupRegistrations = synchronizedMap(new IdentityHashMap<>());
        private Injector injector;
        private LifeCycleManager lifecycle;

        private ResourceRegistration(Key<T> key, CloseAction<? super T> close, boolean standardClose)
        {
            this.key = key;
            this.close = close;
            this.standardClose = standardClose;
        }

        @Inject
        public void initialize(Injector injector, LifeCycleManager lifecycle)
        {
            this.injector = injector;
            this.lifecycle = lifecycle;
        }

        private void registerPending(LifeCycleManager lifecycle, Object instance)
        {
            @SuppressWarnings("unchecked")
            T resource = (T) instance;
            lifecycle.addPendingCloseable(cleanupRegistration(resource), resource, () -> close.close(resource));
        }

        private Object cleanupRegistration(T instance)
        {
            return standardClose ? instance : cleanupRegistrations.computeIfAbsent(instance, _ -> new Object());
        }

        private void register(LifeCycleManager lifecycle, T instance)
        {
            if (standardClose) {
                lifecycle.addCloseable(instance, () -> close.close(instance));
            }
            else {
                // Each custom action is independent of both lifecycle annotations and
                // other registrations for the same resource.
                lifecycle.addCloseAction(cleanupRegistration(instance), instance, () -> close.close(instance));
            }
        }

        @Override
        public Registration get()
        {
            T instance = verifyNotNull(injector.getInstance(key), "null at key %s", key);
            register(lifecycle, instance);
            return new Registration();
        }
    }

    private static final class Registration {}

    private record Cleanup(@ForCleanup Set<Registration> registrations)
    {
        @Inject
        private Cleanup {}
    }

    @Retention(RUNTIME)
    @Target({FIELD, PARAMETER, METHOD})
    @BindingAnnotation
    private @interface ForCleanup {}
}
