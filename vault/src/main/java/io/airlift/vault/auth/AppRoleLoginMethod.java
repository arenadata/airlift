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
 * Logs in with {@code POST /v1/auth/<mount>/login}, using a role id and a secret id.
 * <p>
 * We read {@code vault.auth.approle.secret-id-file} at every login and keep nothing in memory. A
 * secret id is short lived and often works only once, so the tool that gives it to us rewrites the
 * file while the catalog runs.
 */
public final class AppRoleLoginMethod
        implements VaultLoginMethod
{
    private static final JsonCodec<VaultLoginResponse> LOGIN_CODEC = jsonCodec(VaultLoginResponse.class);

    private final VaultHttp http;
    private final String mount;
    private final String roleId;
    private final Optional<String> secretId;
    private final Optional<Path> secretIdFile;

    @Inject
    public AppRoleLoginMethod(VaultHttp http, VaultConnectionConfig config)
    {
        this.http = requireNonNull(http, "http is null");
        requireNonNull(config, "config is null");
        this.mount = config.getAppRoleMount();
        this.roleId = config.getAppRoleRoleId().orElseThrow(() -> new IllegalArgumentException("vault.auth.approle.role-id is not set"));
        this.secretId = config.getAppRoleSecretId();
        this.secretIdFile = config.getAppRoleSecretIdFile().map(File::toPath);
    }

    @Override
    public VaultToken login()
    {
        URI uri = http.uri("auth", mount, "login");
        // we name the mount, the role id and where the secret id comes from. Without that, a
        // rejected login looks the same as a role that expects another secret id
        String operation = format(
                "Failed to log in to Vault at %s using %s with role id '%s' and the secret id from %s",
                uri,
                description(),
                roleId,
                secretIdSource());
        VaultLoginResponse response = http.postCreatingSecret(
                uri,
                // a login carries no token, it produces one
                Optional.empty(),
                ImmutableMap.of("role_id", roleId, "secret_id", secretId()),
                LOGIN_CODEC,
                operation);
        return issuedToken(response, operation);
    }

    @Override
    public String description()
    {
        return format("the AppRole method on mount '%s'", mount);
    }

    private String secretId()
    {
        return secretIdFile
                .map(file -> VaultSecretFile.read(file, "Vault AppRole secret id file"))
                .orElseGet(() -> secretId.orElseThrow(() -> new IllegalStateException("neither vault.auth.approle.secret-id nor vault.auth.approle.secret-id-file is set")));
    }

    private String secretIdSource()
    {
        return secretIdFile
                .map(Path::toString)
                .orElse("'vault.auth.approle.secret-id'");
    }
}
