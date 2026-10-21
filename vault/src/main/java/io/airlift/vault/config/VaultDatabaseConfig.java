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
package io.airlift.vault.config;

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;
import io.airlift.vault.enums.VaultRoleType;
import jakarta.validation.constraints.NotNull;

public class VaultDatabaseConfig
{
    private String databaseMount = "database";
    private VaultRoleType roleType = VaultRoleType.DYNAMIC;
    private String role;

    @NotNull
    public String getDatabaseMount()
    {
        return databaseMount;
    }

    @Config("database-mount")
    @ConfigDescription("Mount path of the database secrets engine")
    public VaultDatabaseConfig setDatabaseMount(String databaseMount)
    {
        this.databaseMount = databaseMount;
        return this;
    }

    @NotNull
    public VaultRoleType getRoleType()
    {
        return roleType;
    }

    @Config("role-type")
    @ConfigDescription("Kind of the database secrets engine role: DYNAMIC or STATIC")
    public VaultDatabaseConfig setRoleType(VaultRoleType roleType)
    {
        this.roleType = roleType;
        return this;
    }

    @NotNull
    public String getRole()
    {
        return role;
    }

    @Config("role")
    @ConfigDescription("Name of the database secrets engine role used to obtain credentials")
    public VaultDatabaseConfig setRole(String role)
    {
        this.role = role;
        return this;
    }
}
