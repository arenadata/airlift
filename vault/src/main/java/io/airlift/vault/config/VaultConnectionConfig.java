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
import io.airlift.configuration.ConfigSecuritySensitive;
import io.airlift.configuration.validation.FileExists;
import io.airlift.vault.enums.VaultAuthMethod;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;

import java.io.File;
import java.net.URI;
import java.util.Optional;

/**
 * Connection and authentication settings shared by the Vault secrets engines.
 * <p>
 * The {@link Config} names have no prefix. The user of the library adds it:
 * {@code buildConfigObject(VaultConnectionConfig.class, "vault")} turns {@code endpoint} into
 * {@code vault.endpoint}, which is how a catalog file spells it. The messages below name the
 * properties with that prefix anyway, because the documentation and the tests quote them word for
 * word.
 */
public class VaultConnectionConfig
{
    /**
     * Where Kubernetes puts the token of a pod, read when a catalog names no file. A constant, so
     * that the description below and the code cannot name different paths.
     */
    public static final String DEFAULT_KUBERNETES_SERVICE_ACCOUNT_TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private URI endpoint;
    private VaultAuthMethod authMethod = VaultAuthMethod.TOKEN;
    private String token;
    private File tokenFile;
    private String appRoleMount = "approle";
    // the mounts carry a default, so the invariants below cannot tell "left alone" from "set to the
    // default" by the value: the setter is what says the catalog named the property at all
    private boolean appRoleMountConfigured;
    private String appRoleRoleId;
    private String appRoleSecretId;
    private File appRoleSecretIdFile;
    private String kubernetesMount = "kubernetes";
    private boolean kubernetesMountConfigured;
    private String kubernetesRole;
    private File kubernetesServiceAccountTokenFile;
    private String namespace;

    @NotNull
    public URI getEndpoint()
    {
        return endpoint;
    }

    @Config("endpoint")
    @ConfigDescription("Base URI of the OpenBao or HashiCorp Vault server")
    public VaultConnectionConfig setEndpoint(URI endpoint)
    {
        this.endpoint = endpoint;
        return this;
    }

    @NotNull
    public VaultAuthMethod getAuthMethod()
    {
        return authMethod;
    }

    @Config("auth.method")
    @ConfigDescription("How Trino authenticates to the server: TOKEN, APPROLE or KUBERNETES")
    public VaultConnectionConfig setAuthMethod(VaultAuthMethod authMethod)
    {
        this.authMethod = authMethod;
        return this;
    }

    public Optional<String> getToken()
    {
        return Optional.ofNullable(token);
    }

    @Config("token")
    @ConfigSecuritySensitive
    @ConfigDescription("Token used to authenticate to the server, mutually exclusive with vault.token-file")
    public VaultConnectionConfig setToken(String token)
    {
        this.token = token;
        return this;
    }

    public Optional<@FileExists File> getTokenFile()
    {
        return Optional.ofNullable(tokenFile);
    }

    @Config("token-file")
    @ConfigDescription("File containing the token used to authenticate to the server, read on every credential refresh")
    public VaultConnectionConfig setTokenFile(File tokenFile)
    {
        this.tokenFile = tokenFile;
        return this;
    }

    @NotNull
    public String getAppRoleMount()
    {
        return appRoleMount;
    }

    @Config("auth.approle.mount")
    @ConfigDescription("Mount path of the AppRole auth method")
    public VaultConnectionConfig setAppRoleMount(String appRoleMount)
    {
        this.appRoleMount = appRoleMount;
        this.appRoleMountConfigured = true;
        return this;
    }

    public Optional<String> getAppRoleRoleId()
    {
        return Optional.ofNullable(appRoleRoleId);
    }

    @Config("auth.approle.role-id")
    @ConfigDescription("Role id of the AppRole Trino logs in with")
    public VaultConnectionConfig setAppRoleRoleId(String appRoleRoleId)
    {
        this.appRoleRoleId = appRoleRoleId;
        return this;
    }

    public Optional<String> getAppRoleSecretId()
    {
        return Optional.ofNullable(appRoleSecretId);
    }

    @Config("auth.approle.secret-id")
    @ConfigSecuritySensitive
    @ConfigDescription("Secret id of the AppRole, mutually exclusive with vault.auth.approle.secret-id-file")
    public VaultConnectionConfig setAppRoleSecretId(String appRoleSecretId)
    {
        this.appRoleSecretId = appRoleSecretId;
        return this;
    }

    public Optional<@FileExists File> getAppRoleSecretIdFile()
    {
        return Optional.ofNullable(appRoleSecretIdFile);
    }

    @Config("auth.approle.secret-id-file")
    @ConfigDescription("File containing the secret id of the AppRole, read on every login")
    public VaultConnectionConfig setAppRoleSecretIdFile(File appRoleSecretIdFile)
    {
        this.appRoleSecretIdFile = appRoleSecretIdFile;
        return this;
    }

    @NotNull
    public String getKubernetesMount()
    {
        return kubernetesMount;
    }

    @Config("auth.kubernetes.mount")
    @ConfigDescription("Mount path of the Kubernetes auth method")
    public VaultConnectionConfig setKubernetesMount(String kubernetesMount)
    {
        this.kubernetesMount = kubernetesMount;
        this.kubernetesMountConfigured = true;
        return this;
    }

    public Optional<String> getKubernetesRole()
    {
        return Optional.ofNullable(kubernetesRole);
    }

    @Config("auth.kubernetes.role")
    @ConfigDescription("Name of the Kubernetes auth method role the service account is bound to")
    public VaultConnectionConfig setKubernetesRole(String kubernetesRole)
    {
        this.kubernetesRole = kubernetesRole;
        return this;
    }

    /**
     * Left empty rather than defaulted to the path the kubelet uses, because {@link FileExists} on
     * that path would fail every catalog running outside Kubernetes, and because an empty value is
     * what tells {@link #isKubernetesConfigurationValid()} that no Kubernetes property was set.
     */
    public Optional<@FileExists File> getKubernetesServiceAccountTokenFile()
    {
        return Optional.ofNullable(kubernetesServiceAccountTokenFile);
    }

    @Config("auth.kubernetes.service-account-token-file")
    @ConfigDescription("File containing the service account token, read on every login, defaults to " + DEFAULT_KUBERNETES_SERVICE_ACCOUNT_TOKEN_FILE)
    public VaultConnectionConfig setKubernetesServiceAccountTokenFile(File kubernetesServiceAccountTokenFile)
    {
        this.kubernetesServiceAccountTokenFile = kubernetesServiceAccountTokenFile;
        return this;
    }

    public Optional<String> getNamespace()
    {
        return Optional.ofNullable(namespace);
    }

    @Config("namespace")
    @ConfigDescription("Namespace sent as the X-Vault-Namespace header")
    public VaultConnectionConfig setNamespace(String namespace)
    {
        this.namespace = namespace;
        return this;
    }

    /**
     * The invariants below are called by bean validation, not from code. Each of them rejects a
     * catalog that names a property the selected authentication method never reads. Without this
     * one, a catalog may set both properties, and the token file quietly wins.
     */
    @AssertTrue(message = "Exactly one of 'vault.token' or 'vault.token-file' must be set")
    public boolean isTokenConfigurationValid()
    {
        return authMethod != VaultAuthMethod.TOKEN || (getToken().isPresent() ^ getTokenFile().isPresent());
    }

    @AssertTrue(message = "'vault.token' and 'vault.token-file' must not be set when vault.auth.method is not TOKEN")
    public boolean isTokenUnusedByOtherMethods()
    {
        return authMethod == VaultAuthMethod.TOKEN || (getToken().isEmpty() && getTokenFile().isEmpty());
    }

    @AssertTrue(message = "'vault.auth.approle.role-id' and exactly one of 'vault.auth.approle.secret-id' or 'vault.auth.approle.secret-id-file' must be set when, and only when, vault.auth.method is APPROLE")
    public boolean isAppRoleConfigurationValid()
    {
        if (authMethod != VaultAuthMethod.APPROLE) {
            return !appRoleMountConfigured && getAppRoleRoleId().isEmpty() && getAppRoleSecretId().isEmpty() && getAppRoleSecretIdFile().isEmpty();
        }
        return getAppRoleRoleId().isPresent() && (getAppRoleSecretId().isPresent() ^ getAppRoleSecretIdFile().isPresent());
    }

    @AssertTrue(message = "'vault.auth.kubernetes.role' must be set when, and only when, vault.auth.method is KUBERNETES")
    public boolean isKubernetesConfigurationValid()
    {
        if (authMethod != VaultAuthMethod.KUBERNETES) {
            return !kubernetesMountConfigured && getKubernetesRole().isEmpty() && getKubernetesServiceAccountTokenFile().isEmpty();
        }
        return getKubernetesRole().isPresent();
    }
}
