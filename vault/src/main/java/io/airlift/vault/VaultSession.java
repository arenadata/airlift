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

import com.google.inject.Inject;
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpClientConfig;
import io.airlift.http.client.jetty.JettyHttpClient;
import io.airlift.vault.auth.AppRoleLoginMethod;
import io.airlift.vault.auth.FileVaultTokenSupplier;
import io.airlift.vault.auth.KerberosLoginMethod;
import io.airlift.vault.auth.KubernetesLoginMethod;
import io.airlift.vault.auth.LoginVaultTokenSupplier;
import io.airlift.vault.auth.StaticVaultTokenSupplier;
import io.airlift.vault.auth.VaultTokenSupplier;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.http.VaultHttpException;
import jakarta.annotation.PreDestroy;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import static com.google.common.base.Preconditions.checkArgument;
import static io.airlift.vault.VaultException.Category.REFUSED;
import static io.airlift.vault.enums.VaultAuthMethod.KERBEROS;
import static java.util.Objects.requireNonNull;

/**
 * One authenticated Vault connection. Engine clients may share it; unrelated callers create
 * independent sessions. Close engine resources before this session, and this session before HTTP.
 */
public final class VaultSession
        implements AutoCloseable
{
    private final VaultHttp http;
    private final VaultTokenSupplier tokenSupplier;
    private final Optional<HttpClient> ownedHttpClient;
    private final AtomicBoolean closed = new AtomicBoolean();

    @Inject
    public VaultSession(VaultHttp http, VaultTokenSupplier tokenSupplier)
    {
        this(http, tokenSupplier, Optional.empty());
    }

    private VaultSession(VaultHttp http, VaultTokenSupplier tokenSupplier, Optional<HttpClient> ownedHttpClient)
    {
        this.http = requireNonNull(http, "http is null");
        this.tokenSupplier = requireNonNull(tokenSupplier, "tokenSupplier is null");
        this.ownedHttpClient = requireNonNull(ownedHttpClient, "ownedHttpClient is null");
    }

    public static VaultSession open(VaultConnectionConfig config, HttpClientConfig httpConfig)
    {
        validate(config);
        validateKerberosHttpConfig(config, httpConfig);
        return owned(new JettyHttpClient("vault", httpConfig), config);
    }

    /**
     * Creates a session which leaves the caller's HTTP client open when closed.
     * The caller must enforce certificate and hostname verification for Kerberos authentication.
     */
    public static VaultSession borrowed(HttpClient httpClient, VaultConnectionConfig config)
    {
        return create(httpClient, config, false);
    }

    /**
     * Takes ownership of HTTP, including closing it if construction fails.
     * The supplied client must enforce certificate and hostname verification for Kerberos authentication.
     */
    public static VaultSession owned(HttpClient httpClient, VaultConnectionConfig config)
    {
        return create(httpClient, config, true);
    }

    private static VaultSession create(HttpClient httpClient, VaultConnectionConfig config, boolean ownsHttp)
    {
        requireNonNull(httpClient, "httpClient is null");
        try {
            validate(config);
            VaultHttp http = new VaultHttp(httpClient, config);
            VaultTokenSupplier supplier = switch (config.getAuthMethod()) {
                case TOKEN -> configuredToken(config);
                case APPROLE -> new LoginVaultTokenSupplier(new AppRoleLoginMethod(http, config), http);
                case KUBERNETES -> new LoginVaultTokenSupplier(new KubernetesLoginMethod(http, config), http);
                case KERBEROS -> new LoginVaultTokenSupplier(new KerberosLoginMethod(http, config), http);
            };
            return new VaultSession(http, supplier, ownsHttp ? Optional.of(httpClient) : Optional.empty());
        }
        catch (RuntimeException | Error failure) {
            if (ownsHttp) {
                httpClient.close();
            }
            throw failure;
        }
    }

    static VaultTokenSupplier configuredToken(VaultConnectionConfig config)
    {
        return config.getTokenFile()
                .<VaultTokenSupplier>map(file -> new FileVaultTokenSupplier(file.toPath()))
                .orElseGet(() -> new StaticVaultTokenSupplier(config.getToken().orElseThrow()));
    }

    static void validateKerberosHttpConfig(VaultConnectionConfig config, HttpClientConfig httpConfig)
    {
        requireNonNull(httpConfig, "httpConfig is null");
        checkArgument(config.getAuthMethod() != KERBEROS || httpConfig.isVerifyHostname(), "Vault Kerberos authentication requires HTTPS hostname verification");
    }

    private static void validate(VaultConnectionConfig config)
    {
        requireNonNull(config, "config is null");
        requireNonNull(config.getEndpoint(), "endpoint is null");
        requireNonNull(config.getAuthMethod(), "authMethod is null");
        checkArgument(config.isTokenConfigurationValid() && config.isTokenUnusedByOtherMethods(), "Invalid Vault token configuration");
        checkArgument(config.isAppRoleConfigurationValid(), "Invalid Vault AppRole configuration");
        checkArgument(config.isKubernetesConfigurationValid(), "Invalid Vault Kubernetes configuration");
        checkArgument(config.isKerberosConfigurationValid(), "Invalid Vault Kerberos configuration");
        checkArgument(config.isKerberosHttpsValid(), "Vault Kerberos authentication requires HTTPS");
    }

    public VaultHttp http()
    {
        return http;
    }

    /**
     * Replays a request at most once after a rejected token, including requests returning null.
     */
    public <T> T withToken(Function<String, T> request)
    {
        requireNonNull(request, "request is null");
        if (closed.get()) {
            throw new VaultException(REFUSED, "The Vault session is closed");
        }
        String token = tokenSupplier.get();
        try {
            return request.apply(token);
        }
        catch (VaultHttpException rejection) {
            if (rejection.statusCode() != 403) {
                throw rejection;
            }
            Optional<String> replacement;
            try {
                replacement = tokenSupplier.tokenAfterRejection(token);
            }
            catch (RuntimeException failure) {
                rejection.addSuppressed(failure);
                throw rejection;
            }
            if (replacement.isEmpty()) {
                throw rejection;
            }
            return request.apply(replacement.orElseThrow());
        }
    }

    @Override
    @PreDestroy
    public void close()
    {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        try {
            tokenSupplier.close();
        }
        finally {
            ownedHttpClient.ifPresent(HttpClient::close);
        }
    }
}
