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

import com.google.common.collect.ImmutableMap;
import com.google.inject.Inject;
import io.airlift.json.JsonCodec;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.model.VaultToken;
import io.airlift.vault.response.VaultLoginResponse;

import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.util.Optional;

import static io.airlift.json.JsonCodec.jsonCodec;
import static io.airlift.vault.auth.VaultLoginMethod.issuedToken;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

/**
 * Logs in with {@code POST /v1/auth/<mount>/login}, using the service account token of the pod. The
 * server checks that token with a {@code TokenReview} call to the Kubernetes API server.
 * <p>
 * We read the token at every login. Kubernetes rewrites it in the same file before it expires, so a
 * token kept in memory would die while the file is still good. The audience is not part of the
 * request: it comes from the pod and from the role on the server, so there is no property for it.
 */
public final class KubernetesLoginMethod
        implements VaultLoginMethod
{
    private static final JsonCodec<VaultLoginResponse> LOGIN_CODEC = jsonCodec(VaultLoginResponse.class);
    private static final Path DEFAULT_SERVICE_ACCOUNT_TOKEN_FILE = Path.of(VaultConnectionConfig.DEFAULT_KUBERNETES_SERVICE_ACCOUNT_TOKEN_FILE);

    private final VaultHttp http;
    private final String mount;
    private final String role;
    private final Path serviceAccountTokenFile;

    @Inject
    public KubernetesLoginMethod(VaultHttp http, VaultConnectionConfig config)
    {
        this.http = requireNonNull(http, "http is null");
        requireNonNull(config, "config is null");
        this.mount = config.getKubernetesMount();
        this.role = config.getKubernetesRole().orElseThrow(() -> new IllegalArgumentException("vault.auth.kubernetes.role is not set"));
        this.serviceAccountTokenFile = config.getKubernetesServiceAccountTokenFile()
                .map(File::toPath)
                .orElse(DEFAULT_SERVICE_ACCOUNT_TOKEN_FILE);
    }

    @Override
    public VaultToken login()
    {
        URI uri = http.uri("auth", mount, "login");
        // "permission denied" here has two reasons: the service account is not allowed to use this
        // role, or the server itself may no longer call the Kubernetes API. The message names
        // everything about the attempt, so an operator can tell them apart
        String operation = format(
                "Failed to log in to Vault at %s using %s as role '%s' with the token from %s",
                uri,
                description(),
                role,
                serviceAccountTokenFile);
        VaultLoginResponse response = http.postCreatingSecret(
                uri,
                // a login carries no token, it produces one
                Optional.empty(),
                ImmutableMap.of("role", role, "jwt", VaultSecretFile.read(serviceAccountTokenFile, "Kubernetes service account token file")),
                LOGIN_CODEC,
                operation);
        return issuedToken(response, operation);
    }

    @Override
    public String description()
    {
        return format("the Kubernetes method on mount '%s'", mount);
    }
}
