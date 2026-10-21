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

import com.google.common.annotations.VisibleForTesting;
import com.google.inject.Binder;
import com.google.inject.Module;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import com.google.inject.spi.ProvisionListener.ProvisionInvocation;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import java.util.List;

import static com.google.inject.matcher.Matchers.any;
import static java.util.Objects.requireNonNull;
import static org.weakref.jmx.guice.ExportBinder.newExporter;

/** Guice module for binding the lifecycle manager. */
public class LifeCycleModule
        implements Module
{
    private final LifeCycleManager lifeCycleManager;
    private final LifeCycleMethodsMap lifeCycleMethodsMap = new LifeCycleMethodsMap();

    @VisibleForTesting
    LifeCycleModule()
    {
        this("LifeCycleManager");
    }

    public LifeCycleModule(String name)
    {
        this(new LifeCycleManager(name, List.of(), null));
    }

    LifeCycleModule(LifeCycleManager lifeCycleManager)
    {
        this.lifeCycleManager = requireNonNull(lifeCycleManager, "lifeCycleManager is null");
    }

    @Override
    public void configure(Binder binder)
    {
        binder.bindListener(any(), this::provision);
        newExporter(binder).export(LifeCycleManager.class).withGeneratedName();
    }

    private <T> void provision(ProvisionInvocation<T> provision)
    {
        Object instance = provision.provision();
        if (instance != null && isLifeCycleClass(instance.getClass())) {
            lifeCycleManager.addInstance(instance);
        }
    }

    private boolean isLifeCycleClass(Class<?> clazz)
    {
        LifeCycleMethods methods = lifeCycleMethodsMap.get(clazz);
        return methods.hasFor(PostConstruct.class) || methods.hasFor(PreDestroy.class);
    }

    @Provides
    @Singleton
    public LifeCycleManager getLifeCycleManager()
    {
        return lifeCycleManager;
    }
}
