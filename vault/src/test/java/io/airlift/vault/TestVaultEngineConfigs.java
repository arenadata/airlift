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

import com.google.common.collect.ImmutableMap;
import io.airlift.vault.config.VaultDatabaseConfig;
import io.airlift.vault.config.VaultKvConfig;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.junit.jupiter.api.Test;

import static io.airlift.configuration.testing.ConfigAssertions.assertFullMapping;
import static io.airlift.configuration.testing.ConfigAssertions.assertRecordedDefaults;
import static io.airlift.configuration.testing.ConfigAssertions.recordDefaults;
import static io.airlift.testing.ValidationAssertions.assertFailsValidation;
import static io.airlift.vault.enums.VaultRoleType.DYNAMIC;
import static io.airlift.vault.enums.VaultRoleType.STATIC;

class TestVaultEngineConfigs
{
    @Test
    void testDatabaseConfig()
    {
        assertRecordedDefaults(recordDefaults(VaultDatabaseConfig.class)
                .setDatabaseMount("database")
                .setRoleType(DYNAMIC)
                .setRole(null));
        assertFullMapping(ImmutableMap.of("database-mount", "team/database", "role-type", "STATIC", "role", "reader"),
                new VaultDatabaseConfig().setDatabaseMount("team/database").setRoleType(STATIC).setRole("reader"));
    }

    @Test
    void testKvConfig()
    {
        assertRecordedDefaults(recordDefaults(VaultKvConfig.class).setMount("secret").setVersion(2));
        assertFullMapping(ImmutableMap.of("kv.mount", "team/kv", "kv.version", "1"), new VaultKvConfig().setMount("team/kv").setVersion(1));
        assertFailsValidation(new VaultKvConfig().setVersion(0), "version", "must be greater than or equal to 1", Min.class);
        assertFailsValidation(new VaultKvConfig().setVersion(3), "version", "must be less than or equal to 2", Max.class);
    }
}
