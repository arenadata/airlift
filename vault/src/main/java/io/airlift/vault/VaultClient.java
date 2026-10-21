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

import com.google.common.collect.ImmutableMap;
import com.google.inject.Inject;
import io.airlift.json.JsonCodec;
import io.airlift.log.Logger;
import io.airlift.vault.config.VaultDatabaseConfig;
import io.airlift.vault.enums.VaultRoleType;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.http.VaultHttpException;
import io.airlift.vault.model.VaultCredentials;
import io.airlift.vault.response.VaultDynamicCredentialsResponse;
import io.airlift.vault.response.VaultLeaseRenewalResponse;
import io.airlift.vault.response.VaultStaticCredentialsResponse;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

import static com.google.common.base.Strings.isNullOrEmpty;
import static io.airlift.json.JsonCodec.jsonCodec;
import static java.lang.Math.max;
import static java.lang.Math.round;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

/**
 * Reads database credentials from the OpenBao or HashiCorp Vault database secrets engine and keeps
 * the lease behind them alive.
 * <p>
 * Repeating a failed request is the work of {@link VaultHttp}. Only one request here is special: a
 * read of a dynamic role creates a database account, so we repeat it only when the server surely did
 * not serve it. An account we do not know about can still be left behind, and it disappears when its
 * lease ends.
 */
public class VaultClient
{
    private static final Logger log = Logger.get(VaultClient.class);

    private static final JsonCodec<VaultDynamicCredentialsResponse> DYNAMIC_CREDENTIALS_CODEC = jsonCodec(VaultDynamicCredentialsResponse.class);
    private static final JsonCodec<VaultStaticCredentialsResponse> STATIC_CREDENTIALS_CODEC = jsonCodec(VaultStaticCredentialsResponse.class);
    private static final JsonCodec<VaultLeaseRenewalResponse> LEASE_RENEWAL_CODEC = jsonCodec(VaultLeaseRenewalResponse.class);

    private final VaultHttp http;
    private final VaultSession session;
    private final String databaseMount;
    private final String role;
    private final VaultRoleType roleType;

    @Inject
    public VaultClient(VaultSession session, VaultDatabaseConfig config)
    {
        this.session = requireNonNull(session, "session is null");
        this.http = session.http();
        requireNonNull(config, "config is null");
        this.databaseMount = config.getDatabaseMount();
        this.role = config.getRole();
        this.roleType = config.getRoleType();
    }

    public VaultCredentials readCredentials()
    {
        return session.withToken(this::readCredentials);
    }

    /**
     * Extends the lease behind the cached credentials.
     *
     * @return how long the lease still lives, or empty when the server refused. A lease it does not
     *         know, or one that ended, comes back as HTTP 400. That is normal for a catalog that runs
     *         for a long time, not a failure
     */
    public Optional<Duration> renewLease(String leaseId)
    {
        requireNonNull(leaseId, "leaseId is null");
        URI uri = http.uri("sys", "leases", "renew");
        String operation = format("Failed to renew the Vault lease of the credentials for role '%s' at %s", role, uri);
        try {
            VaultLeaseRenewalResponse response = session.withToken(token -> postLeaseRenewal(uri, leaseId, token, operation));
            // the server keeps the lease but stops extending it once max_ttl is in sight, and it
            // clears renewable when the lease is on its last stretch
            if (!response.renewable() || response.leaseDuration() <= 0) {
                return Optional.empty();
            }
            return Optional.of(Duration.ofSeconds(response.leaseDuration()));
        }
        catch (VaultHttpException e) {
            if (e.statusCode() == 403) {
                log.warn(e, "Vault rejected the token while renewing the lease of the credentials for role '%s'", role);
                return Optional.empty();
            }
            if (e.statusCode() >= 400 && e.statusCode() < 500) {
                log.debug(e, "Vault refused to renew the lease of the credentials for role '%s'", role);
                return Optional.empty();
            }
            throw e;
        }
    }

    /**
     * Revokes the lease. It runs while the connector shuts down, so a failure goes to the log
     * instead of an exception: a lease nobody revoked expires by itself, while an exception here
     * would stop the steps after it. Revoking a lease that already ended does nothing on the server,
     * so calling this twice is safe.
     */
    public boolean revokeLease(String leaseId)
    {
        requireNonNull(leaseId, "leaseId is null");
        URI uri = http.uri("sys", "leases", "revoke");
        String operation = format("Failed to revoke the Vault lease of the credentials for role '%s' at %s", role, uri);
        try {
            // sync is not requested: the queued default answers faster, and revocations run serially
            // while the server is shutting down. A token that expired while the catalog was running
            // must not cost us the revocation either, hence the replay withToken makes
            session.withToken(token -> {
                http.postExpectingNoContent(uri, token, ImmutableMap.of("lease_id", leaseId), operation);
                return null;
            });
            return true;
        }
        // deliberately every runtime failure, including one of our own making: this runs while the
        // connector is shutting down, and an exception thrown here would abort the steps after it.
        // An unrevoked lease still expires at the end of its TTL
        catch (RuntimeException e) {
            log.warn(e, "Failed to revoke the Vault lease of the credentials for role '%s' at %s", role, uri);
            return false;
        }
    }

    private VaultCredentials readCredentials(String token)
    {
        return switch (roleType) {
            case DYNAMIC -> readDynamicCredentials(token);
            case STATIC -> readStaticCredentials(token);
        };
    }

    private VaultCredentials readDynamicCredentials(String token)
    {
        URI uri = credentialsUri("creds");
        String operation = readOperation(uri);
        VaultDynamicCredentialsResponse response = http.getCreatingSecret(uri, Optional.of(token), DYNAMIC_CREDENTIALS_CODEC, operation);
        if (response.data() == null) {
            throw malformedResponse(operation, "response has no 'data' object");
        }
        return new VaultCredentials(
                requireCredentialPart(operation, response.data().username(), "username"),
                requireCredentialPart(operation, response.data().password(), "password"),
                Duration.ofSeconds(max(response.leaseDuration(), 0)),
                Optional.ofNullable(response.leaseId()).filter(leaseId -> !leaseId.isEmpty()),
                response.renewable());
    }

    private VaultCredentials readStaticCredentials(String token)
    {
        URI uri = credentialsUri("static-creds");
        String operation = readOperation(uri);
        VaultStaticCredentialsResponse response = http.get(uri, Optional.of(token), STATIC_CREDENTIALS_CODEC, operation);
        if (response.data() == null) {
            throw malformedResponse(operation, "response has no 'data' object");
        }
        return new VaultCredentials(
                requireCredentialPart(operation, response.data().username(), "username"),
                requireCredentialPart(operation, response.data().password(), "password"),
                staticLifetime(response.data().ttl()),
                Optional.empty(),
                false);
    }

    /**
     * How long static credentials still live. They have no lease, the server sends the time to the
     * next rotation as {@code data.ttl} in fractional seconds. We keep milliseconds: rounding the
     * last part of a second down to zero would mean "the server said nothing" to the provider, which
     * would then keep a password the server is about to change for a whole {@code credential-max-ttl}.
     */
    private static Duration staticLifetime(Double ttl)
    {
        if (ttl == null) {
            return Duration.ZERO;
        }
        return Duration.ofMillis(max(round(ttl * 1000), 0));
    }

    private VaultLeaseRenewalResponse postLeaseRenewal(URI uri, String leaseId, String token, String operation)
    {
        // no increment is sent: the default TTL configured on the role is the right one, and the
        // field is advisory anyway
        return http.post(uri, Optional.of(token), ImmutableMap.of("lease_id", leaseId), LEASE_RENEWAL_CODEC, operation);
    }

    private String readOperation(URI uri)
    {
        return format("Failed to read credentials for role '%s' from Vault at %s", role, uri);
    }

    /**
     * The server answered, and the answer is unusable. The status carried by the exception is the one
     * of that answer, {@code 200}: the request did complete, and callers that look at the status are
     * asking whether the server refused them, not whether the body parsed.
     */
    private VaultHttpException malformedResponse(String operation, String reason)
    {
        return new VaultHttpException(VaultException.Category.REFUSED, 200, format("%s: %s", operation, reason));
    }

    private String requireCredentialPart(String operation, String value, String name)
    {
        if (isNullOrEmpty(value)) {
            throw malformedResponse(operation, format("response has no '%s', the role must issue credentials of type password", name));
        }
        return value;
    }

    private URI credentialsUri(String credentialsPath)
    {
        return http.uri(databaseMount, credentialsPath, role);
    }
}
