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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.reflect.ClassPath;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.RecordComponent;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A record that holds a secret must not print it. The generated {@code toString} of a record prints
 * every component, so every such record overrides it, and this test is what keeps those overrides
 * in place: deleting one is easy, and the password would then reach the first log line that prints
 * the object.
 * <p>
 * The package and everything below it is scanned instead of a list written here, so a record added
 * later is checked too, without anybody remembering to come back to this test.
 */
public class TestVaultRecordsHideSecrets
{
    private static final String MARKER = "S3CR3T-must-not-be-printed";

    /**
     * Components that hold something nobody may see. The name is what we go by: the fields of these
     * records are named after the JSON of the server, and the server calls a secret a secret.
     */
    private static final Set<String> SECRET_COMPONENTS = ImmutableSet.of("password", "clientToken", "secretId", "token");

    /**
     * The records we know hold a secret today. If a rename or a move makes one of them invisible to
     * the scan, this test says so instead of passing quietly.
     */
    private static final Set<String> EXPECTED = ImmutableSet.of(
            "VaultCredentials",
            "VaultToken",
            "DynamicCredentialsData",
            "StaticCredentialsData",
            "VaultLoginResponse$Auth");

    @Test
    public void testNoRecordPrintsItsSecret()
            throws Exception
    {
        ImmutableList.Builder<Class<?>> withSecrets = ImmutableList.builder();
        for (Class<?> clazz : recordsOfThePackage()) {
            if (hasSecretComponent(clazz)) {
                withSecrets.add(clazz);
                Object instance = instantiate(clazz);
                assertThat(instance.toString())
                        .as("toString of %s", clazz.getSimpleName())
                        .doesNotContain(MARKER);
            }
        }
        assertThat(withSecrets.build().stream().map(TestVaultRecordsHideSecrets::name).collect(toImmutableList()))
                .as("records holding a secret")
                .containsAll(EXPECTED);
    }

    private static List<Class<?>> recordsOfThePackage()
            throws IOException
    {
        ImmutableList.Builder<Class<?>> records = ImmutableList.builder();
        for (ClassPath.ClassInfo info : ClassPath.from(TestVaultRecordsHideSecrets.class.getClassLoader()).getTopLevelClassesRecursive("io.airlift.vault")) {
            Class<?> clazz = info.load();
            collectRecords(clazz, records);
        }
        return records.build();
    }

    private static void collectRecords(Class<?> clazz, ImmutableList.Builder<Class<?>> records)
    {
        if (clazz.isRecord()) {
            records.add(clazz);
        }
        // a record nested in another one, such as the auth object of a login response
        for (Class<?> nested : clazz.getDeclaredClasses()) {
            collectRecords(nested, records);
        }
    }

    private static boolean hasSecretComponent(Class<?> clazz)
    {
        for (RecordComponent component : clazz.getRecordComponents()) {
            if (SECRET_COMPONENTS.contains(component.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds a record whose secret components hold the marker, so that a {@code toString} printing
     * one of them is caught. Only the types the records of this package use are supported: a new type makes
     * the test fail here, which is better than skipping the record without a word.
     */
    private static Object instantiate(Class<?> clazz)
            throws Exception
    {
        RecordComponent[] components = clazz.getRecordComponents();
        Class<?>[] types = new Class<?>[components.length];
        Object[] values = new Object[components.length];
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType();
            values[i] = value(components[i], clazz.getSimpleName() + "." + components[i].getName());
        }
        Constructor<?> constructor = clazz.getDeclaredConstructor(types);
        // a record nested in a class of the package can be private, CachedToken is
        constructor.setAccessible(true);
        return constructor.newInstance(values);
    }

    private static Object value(RecordComponent component, String where)
    {
        Class<?> type = component.getType();
        // only a secret carries the marker: a user name is printed on purpose, and a test that
        // marked it as well would call every toString a leak
        boolean secret = SECRET_COMPONENTS.contains(component.getName());
        if (type == String.class) {
            return secret ? MARKER : "visible-" + component.getName();
        }
        if (type == Duration.class) {
            return Duration.ofSeconds(60);
        }
        if (type == boolean.class) {
            return true;
        }
        if (type == long.class) {
            return 60L;
        }
        if (type == Double.class) {
            return 60.0;
        }
        if (type == Optional.class) {
            return Optional.of(secret ? MARKER : "visible-" + component.getName());
        }
        if (type == List.class) {
            return ImmutableList.of("visible-" + component.getName());
        }
        if (type.isRecord()) {
            try {
                return instantiate(type);
            }
            catch (Exception e) {
                throw new AssertionError("cannot build the nested record of " + where, e);
            }
        }
        throw new AssertionError("no test value for %s of %s, add one".formatted(type.getSimpleName(), where));
    }

    private static String name(Class<?> clazz)
    {
        Class<?> enclosing = clazz.getEnclosingClass();
        return enclosing == null ? clazz.getSimpleName() : enclosing.getSimpleName() + "$" + clazz.getSimpleName();
    }
}
