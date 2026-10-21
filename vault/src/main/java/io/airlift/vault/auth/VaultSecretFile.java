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

import io.airlift.vault.VaultException;

import java.io.IOException;
import java.nio.file.Path;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.readString;

/**
 * Reads a secret from a file. Three of them exist: the token of {@code vault.token-file}, the
 * secret id of {@code vault.auth.approle.secret-id-file}, and the service account token that
 * Kubernetes puts into a pod. Somebody outside Trino writes all three: an operator, {@code bao
 * agent} or the kubelet.
 * <p>
 * We read the file every time and never keep the value: a secret id often works only once, and
 * Kubernetes rewrites the token of a pod while it runs. This happens rarely, once per login or per
 * new credentials.
 */
final class VaultSecretFile
{
    private VaultSecretFile() {}

    /**
     * Reads the file and returns what is in it, without the spaces and the line break around it. A
     * file we cannot read and a file with nothing in it are both errors: an empty secret would only
     * come back from the server as a refusal, and the message about a file says much more.
     *
     * @param description what is in the file, used in the error message, for example
     *         {@code "Vault token file"}
     */
    public static String read(Path file, String description)
    {
        String content;
        try {
            content = readString(file, UTF_8);
        }
        catch (IOException e) {
            throw new VaultException(VaultException.Category.REFUSED, format("Failed to read %s %s", description, file), e);
        }
        String secret = content.strip();
        if (secret.isEmpty()) {
            throw new VaultException(VaultException.Category.REFUSED, format("%s %s is empty", description, file));
        }
        return secret;
    }
}
