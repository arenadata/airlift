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
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

public class VaultKvConfig
{
    private String mount = "secret";
    private int version = 2;

    @NotBlank
    public String getMount()
    {
        return mount;
    }

    @Config("kv.mount")
    @ConfigDescription("Mount path of the KV secrets engine")
    public VaultKvConfig setMount(String mount)
    {
        this.mount = mount;
        return this;
    }

    @Min(1)
    @Max(2)
    public int getVersion()
    {
        return version;
    }

    @Config("kv.version")
    @ConfigDescription("KV secrets engine version: 1 or 2")
    public VaultKvConfig setVersion(int version)
    {
        this.version = version;
        return this;
    }
}
