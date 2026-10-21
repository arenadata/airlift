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
package io.airlift.vault.auth;

import java.nio.file.Path;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * The token from {@code vault.token-file}. We read the file every time, so a new token written by
 * an agent or by Kubernetes is used without a restart of the catalog. This happens rarely, because
 * credentials are kept until they expire.
 */
public class FileVaultTokenSupplier
        implements VaultTokenSupplier
{
    private final Path file;

    public FileVaultTokenSupplier(Path file)
    {
        this.file = requireNonNull(file, "file is null");
    }

    @Override
    public String get()
    {
        return VaultSecretFile.read(file, "Vault token file");
    }

    /**
     * Somebody may have written a new token into the file, so the request is worth repeating when
     * the file changed. We read the file once and repeat with what we read. Reading it a second time
     * would hide the rejection behind an error about a file that is gone.
     */
    @Override
    public Optional<String> tokenAfterRejection(String rejectedToken)
    {
        String token = get();
        return token.equals(rejectedToken) ? Optional.empty() : Optional.of(token);
    }
}
