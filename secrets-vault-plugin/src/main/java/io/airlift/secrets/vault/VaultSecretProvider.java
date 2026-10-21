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
package io.airlift.secrets.vault;

import io.airlift.bootstrap.Bootstrap;
import io.airlift.spi.secrets.SecretProvider;
import io.airlift.vault.VaultException;
import io.airlift.vault.VaultKvClient;
import io.airlift.vault.VaultSecretException;

import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Objects.requireNonNull;

public final class VaultSecretProvider
        implements SecretProvider
{
    private final VaultKvClient client;
    private final Bootstrap bootstrap;
    private final AtomicBoolean closed = new AtomicBoolean();

    VaultSecretProvider(VaultKvClient client, Bootstrap bootstrap)
    {
        this.client = requireNonNull(client, "client is null");
        this.bootstrap = requireNonNull(bootstrap, "bootstrap is null");
    }

    @Override
    public String resolveSecretValue(String reference)
    {
        if (closed.get()) {
            throw new IllegalStateException("Vault secrets provider is closed");
        }
        int separator = reference == null ? -1 : reference.indexOf('#');
        if (separator <= 0 || separator == reference.length() - 1 || separator != reference.lastIndexOf('#')) {
            throw new IllegalArgumentException("Vault secret reference must have the form path#key");
        }
        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        try {
            thread.setContextClassLoader(getClass().getClassLoader());
            return client.readSecretValue(reference.substring(0, separator), reference.substring(separator + 1));
        }
        catch (VaultSecretException failure) {
            String reason = switch (failure.reason()) {
                case MISSING_OR_NON_STRING_FIELD -> "field is missing or is not a string";
                case INVALID_RESPONSE -> "invalid KV response";
                case DELETED_OR_DESTROYED -> "secret version was deleted or destroyed";
            };
            throw new IllegalArgumentException("Unable to resolve Vault secret: " + reason);
        }
        catch (VaultException failure) {
            String status = failure.httpStatusCode().isPresent() ? ", HTTP " + failure.httpStatusCode().getAsInt() : "";
            throw new IllegalArgumentException("Unable to resolve Vault secret (" + failure.category() + status + ")");
        }
        catch (RuntimeException failure) {
            // The resolver forwards exception messages into server configuration errors. Do not
            // attach the original cause: paths, response bodies and credentials must stay private.
            throw new IllegalArgumentException("Unable to resolve Vault secret");
        }
        finally {
            thread.setContextClassLoader(previous);
        }
    }

    @Override
    public void close()
    {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        try {
            bootstrap.close();
        }
        catch (RuntimeException failure) {
            throw new IllegalStateException("Unable to close Vault secrets provider");
        }
    }
}
