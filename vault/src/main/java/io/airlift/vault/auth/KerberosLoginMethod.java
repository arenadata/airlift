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

import com.google.common.annotations.VisibleForTesting;
import com.google.inject.Inject;
import io.airlift.json.JsonCodec;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.model.VaultToken;
import io.airlift.vault.response.VaultLoginResponse;

import java.util.function.Supplier;

import static com.google.common.base.Preconditions.checkArgument;
import static io.airlift.json.JsonCodec.jsonCodec;
import static io.airlift.vault.auth.VaultLoginMethod.issuedToken;
import static java.util.Objects.requireNonNull;

/**
 * OpenBao's single-leg Kerberos client authentication over verified HTTPS. No Kerberos mutual
 * authentication is claimed: the server does not return an AP-REP. TLS authenticates the server.
 */
public final class KerberosLoginMethod
        implements VaultLoginMethod
{
    private static final JsonCodec<VaultLoginResponse> LOGIN_CODEC = jsonCodec(VaultLoginResponse.class);

    private final VaultHttp http;
    private final String mount;
    private final String role;
    private final Supplier<String> negotiateToken;

    @Inject
    public KerberosLoginMethod(VaultHttp http, VaultConnectionConfig config)
    {
        this(http, config, new KerberosTokenGenerator(config));
    }

    @VisibleForTesting
    KerberosLoginMethod(VaultHttp http, VaultConnectionConfig config, Supplier<String> negotiateToken)
    {
        this.http = requireNonNull(http, "http is null");
        requireNonNull(config, "config is null");
        checkArgument(config.isKerberosConfigurationValid() && config.isKerberosHttpsValid(), "Invalid Vault Kerberos configuration");
        this.mount = config.getKerberosMount();
        this.role = config.getKerberosRole().orElseThrow();
        this.negotiateToken = requireNonNull(negotiateToken, "negotiateToken is null");
    }

    @Override
    public VaultToken login()
    {
        String operation = "Failed to log in to Vault using " + description();
        return issuedToken(http.postKerberosLogin(mount, role, negotiateToken, LOGIN_CODEC, operation), operation);
    }

    @Override
    public String description()
    {
        return "the Kerberos method on mount '" + mount + "'";
    }
}
