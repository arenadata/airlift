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

import com.google.common.net.MediaType;
import io.airlift.http.client.HeaderName;
import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.Request;
import io.airlift.http.client.Response;
import io.airlift.http.client.StaticBodyGenerator;
import io.airlift.http.client.testing.TestingHttpClient;
import io.airlift.http.client.testing.TestingResponse;
import io.airlift.testing.TestingTicker;
import io.airlift.vault.VaultClient;
import io.airlift.vault.VaultException;
import io.airlift.vault.VaultSession;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.config.VaultDatabaseConfig;
import io.airlift.vault.http.VaultHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static io.airlift.concurrent.Threads.daemonThreadsNamed;
import static io.airlift.vault.VaultException.Category.REFUSED;
import static io.airlift.vault.VaultException.Category.UNAVAILABLE;
import static io.airlift.vault.auth.LoginVaultTokenSupplier.MAX_SUPERSEDED_TOKENS;
import static io.airlift.vault.enums.VaultAuthMethod.APPROLE;
import static io.airlift.vault.enums.VaultAuthMethod.KUBERNETES;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.Executors.newFixedThreadPool;
import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Authentication against an auth mount: the login itself, the lifecycle of the token it issues, its
 * revocation when the catalog goes away and the single replay of a request the server rejected.
 * <p>
 * The lifetime of a token is measured on a {@link TestingTicker}, and the refresh point carries ten
 * percent of jitter, so every test moves the ticker to a value that is unambiguously before or after
 * the whole jitter band.
 */
public class TestVaultLoginTokenSupplier
{
    /**
     * The consumer of the library picks the codes, so a test of the library picks two of its own. What
     * the assertions rest on is unchanged: a failure worth repeating and a refusal stay told apart.
     */

    private static final URI ENDPOINT = URI.create("http://openbao.invalid:8200");
    private static final String ROLE_ID = "3b7d0f36-0a11-4f0e-9f6c-1f9c2a5f1c11";
    private static final String SECRET_ID = "8f2b2e1a-6b9e-4d70-9d6e-2b1d1f4a5c22";
    private static final String FIRST_TOKEN = "hvs.CAESIFirstIssuedToken";
    private static final String SECOND_TOKEN = "hvs.CAESISecondIssuedToken";
    private static final String USER = "v-approle-trino-dy-x9Kq3Yy2Xn8LQ0-1774000000";
    private static final String PASSWORD = "A1a-8s0Ez7fSb7yqM2Rk";

    private static final String APPROLE_LOGIN_PATH = "/v1/auth/approle/login";
    private static final String KUBERNETES_LOGIN_PATH = "/v1/auth/kubernetes/login";
    private static final String RENEW_SELF_PATH = "/v1/auth/token/renew-self";
    private static final String REVOKE_SELF_PATH = "/v1/auth/token/revoke-self";
    private static final String LOOKUP_SELF_PATH = "/v1/auth/token/lookup-self";
    private static final String CREDENTIALS_PATH = "/v1/database/creds/trino-dynamic";

    private static final String PERMISSION_DENIED = "{\"errors\":[\"permission denied\"]}";
    private static final String SEALED = "{\"errors\":[\"Vault is sealed\"]}";

    // auth/token/lookup-self of a token the server still knows, trimmed to the fields of interest
    private static final String LOOKUP_RESPONSE =
            """
            {"data": {"display_name": "approle", "policies": ["default", "trino"], "renewable": true, "ttl": 3540}}
            """;

    private static final String CREDENTIALS_RESPONSE =
            """
            {
              "lease_id": "database/creds/trino-dynamic/tCq1V0hZ3Zc2u1jH1n1cQxWl",
              "renewable": false,
              "lease_duration": 3600,
              "data": {"username": "%s", "password": "%s"}
            }
            """.formatted(USER, PASSWORD);

    // runs the callers of the requests a test keeps unanswered while it exercises a concurrent path
    private final ExecutorService executor = newFixedThreadPool(2, daemonThreadsNamed("test-vault-login-%s"));

    @AfterEach
    public void stopExecutor()
    {
        executor.shutdownNow();
    }

    @Test
    public void testAppRoleLoginIssuesTheTokenUsedForCredentials()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 3600, true));
            case CREDENTIALS_PATH -> ok(CREDENTIALS_RESPONSE);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);

        Request login = fixture.processor().requests(APPROLE_LOGIN_PATH).getFirst();
        assertThat(login.getMethod()).isEqualTo("POST");
        assertThat(login.getUri()).isEqualTo(URI.create(ENDPOINT + APPROLE_LOGIN_PATH));
        // the login is what produces a token, so it must not carry one
        assertThat(login.getHeader(HeaderName.of("X-Vault-Token"))).isNull();
        assertThat(body(login))
                .contains("\"role_id\" : \"" + ROLE_ID + "\"")
                .contains("\"secret_id\" : \"" + SECRET_ID + "\"");

        assertThat(fixture.processor().requests(CREDENTIALS_PATH).getFirst().getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(FIRST_TOKEN);
        // the token is cached, the second read logs in again only when it expires
        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
    }

    @Test
    public void testSecretIdFileIsReadOnEveryLogin(@TempDir Path tempDir)
            throws IOException
    {
        Path secretIdFile = tempDir.resolve("secret-id");
        Files.writeString(secretIdFile, "first-secret-id\n", UTF_8);
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(
                appRoleConfig()
                        .setAppRoleSecretId(null)
                        .setAppRoleSecretIdFile(secretIdFile.toFile()),
                ticker,
                (request, _) -> switch (path(request)) {
                    // the token is not renewable, so the only way to refresh it is another login
                    case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60, false));
                    case CREDENTIALS_PATH -> ok(CREDENTIALS_RESPONSE);
                    default -> throw new AssertionError("unexpected request " + request.getUri());
                });

        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);
        // a secret id is short lived and often single use, so the orchestrator rewrites the file
        Files.writeString(secretIdFile, "second-secret-id\n", UTF_8);
        ticker.increment(45, SECONDS);
        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);

        List<Request> tokenRequests = fixture.processor().requests(APPROLE_LOGIN_PATH);
        assertThat(tokenRequests).hasSize(2);
        assertThat(body(tokenRequests.get(0))).contains("first-secret-id");
        assertThat(body(tokenRequests.get(1))).contains("second-secret-id");
        assertThat(fixture.processor().requests(CREDENTIALS_PATH).getLast().getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(SECOND_TOKEN);
    }

    @Test
    public void testTokenWithoutLifetimeIsNeverRefreshed()
    {
        TestingTicker ticker = new TestingTicker();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            // a token with no lifetime is what a root token looks like, and it never expires
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 0, false));
            case CREDENTIALS_PATH -> ok(CREDENTIALS_RESPONSE);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(365, DAYS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);

        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
        assertThat(fixture.processor().requests(RENEW_SELF_PATH)).isEmpty();
    }

    @Test
    public void testRenewSelfIsPreferredOverANewLogin()
    {
        TestingTicker ticker = new TestingTicker();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 60, true));
            case RENEW_SELF_PATH -> ok(loginResponse(FIRST_TOKEN, 60, true));
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        // past two thirds of the lifetime including the whole jitter band
        ticker.increment(45, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);

        Request renewal = fixture.processor().requests(RENEW_SELF_PATH).getFirst();
        assertThat(renewal.getMethod()).isEqualTo("POST");
        assertThat(renewal.getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(FIRST_TOKEN);
        // renewing creates no token in the storage backend, so no second login happened
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
    }

    @Test
    public void testRenewalThatNoLongerExtendsForcesANewLogin()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60, true));
            // the maximum TTL of the token is in sight, so renewal grants less than what is left
            case RENEW_SELF_PATH -> ok(loginResponse(FIRST_TOKEN, 3, true));
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(55, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);

        assertThat(fixture.processor().requests(RENEW_SELF_PATH)).hasSize(1);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);
    }

    @Test
    public void testRefusedRenewalFallsBackToALogin()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60, true));
            // a token the server no longer knows, or a policy that does not allow renewal
            case RENEW_SELF_PATH -> response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(45, SECONDS);
        // a refused renewal is a normal outcome, not a failure of the query that needed the token
        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);
    }

    @Test
    public void testBatchTokenIsNotRenewed()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            // a batch token is not stored on the server and can only be replaced
            case APPROLE_LOGIN_PATH -> ok(batchLoginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60));
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(45, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);

        assertThat(fixture.processor().requests(RENEW_SELF_PATH)).isEmpty();
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);
    }

    @Test
    public void testLifetimeComesFromTheAuthObject()
    {
        String misleadingResponse =
                """
                {
                  "lease_id": "",
                  "lease_duration": 3600,
                  "renewable": true,
                  "auth": {"client_token": "%s", "lease_duration": 60, "renewable": false, "token_type": "service"}
                }
                """.formatted(FIRST_TOKEN);
        TestingTicker ticker = new TestingTicker();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(misleadingResponse);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        // the top level of a login response describes the secret it returned, which is none: reading
        // the hour reported there would keep an expired token in use
        ticker.increment(45, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);
        assertThat(fixture.processor().requests(RENEW_SELF_PATH)).isEmpty();
    }

    @Test
    public void testCachedTokenIsUsedWhileTheServerIsUnavailable()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> logins.getAndIncrement() == 0
                    ? ok(loginResponse(FIRST_TOKEN, 60, false))
                    : response(HttpStatus.SERVICE_UNAVAILABLE, SEALED);
            case CREDENTIALS_PATH -> ok(CREDENTIALS_RESPONSE);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);
        ticker.increment(45, SECONDS);
        // the token still has a third of its lifetime left, so a sealed server does not fail the query
        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);
        assertThat(fixture.processor().requests(CREDENTIALS_PATH).getLast().getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(FIRST_TOKEN);

        // once the token is expired the failure of the login is the failure of the read
        ticker.increment(30, SECONDS);
        assertThatThrownBy(() -> fixture.client().readCredentials())
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("HTTP 503");
    }

    @Test
    public void testRejectedTokenIsReplayedExactlyOnce()
    {
        AtomicInteger logins = new AtomicInteger();
        AtomicInteger reads = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 3600, true));
            // the token was revoked between the login and the read, so the server does not know it
            case LOOKUP_SELF_PATH -> response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            // the token issued next works
            case CREDENTIALS_PATH -> reads.getAndIncrement() == 0
                    ? response(HttpStatus.FORBIDDEN, PERMISSION_DENIED)
                    : ok(CREDENTIALS_RESPONSE);
            case REVOKE_SELF_PATH -> response(HttpStatus.NO_CONTENT, "");
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);

        List<Request> credentialRequests = fixture.processor().requests(CREDENTIALS_PATH);
        assertThat(credentialRequests).hasSize(2);
        assertThat(credentialRequests.get(0).getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(FIRST_TOKEN);
        assertThat(credentialRequests.get(1).getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(SECOND_TOKEN);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);

        // the shutdown is what makes the next assertion able to fail: revoke-self is reachable from
        // nowhere else, so without it the test would pass even if the rejected token were remembered
        fixture.shutdown();

        // only the token that still works is revoked. The one the server no longer knows is gone from
        // the token store already, and revoking it would cost a request rejected exactly like the read
        List<Request> revocations = fixture.processor().requests(REVOKE_SELF_PATH);
        assertThat(revocations).hasSize(1);
        assertThat(revocations.getFirst().getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(SECOND_TOKEN);
    }

    @Test
    public void testSecondRejectionIsNotReplayed()
    {
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 3600, true));
            case LOOKUP_SELF_PATH -> response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            case CREDENTIALS_PATH -> response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThatThrownBy(() -> fixture.client().readCredentials())
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("HTTP 403")
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(REFUSED);

        // the freshly issued token was rejected too, and repeating the login would be a self
        // inflicted login storm
        assertThat(fixture.processor().requests(CREDENTIALS_PATH)).hasSize(2);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);
        assertThat(fixture.processor().requests(LOOKUP_SELF_PATH)).hasSize(1);
    }

    @Test
    public void testRejectionTheTokenSurvivesIsNotAnsweredWithALogin()
    {
        // the policy of the AppRole does not cover the role of this catalog, which is what an
        // operator sees after a capability is taken away from a working setup
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 3600, true));
            // the server knows the token, so the rejection is about what it is allowed to do
            case LOOKUP_SELF_PATH -> ok(LOOKUP_RESPONSE);
            case CREDENTIALS_PATH -> response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        for (int read = 0; read < 5; read++) {
            assertThatThrownBy(() -> fixture.client().readCredentials())
                    .isInstanceOf(VaultException.class)
                    .hasMessageContaining("HTTP 403");
        }

        // one login for all of them, and no replay: another token would carry the same policies
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
        assertThat(fixture.processor().requests(CREDENTIALS_PATH)).hasSize(5);
        assertThat(fixture.processor().requests(LOOKUP_SELF_PATH)).hasSize(5);
        // the token is still the one the catalog works with, so it stays in the cache
        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
    }

    @Test
    public void testRejectionIsReportedWhenTheLookupCannotBeAnswered()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 3600, true));
            case LOOKUP_SELF_PATH -> response(HttpStatus.SERVICE_UNAVAILABLE, SEALED);
            case CREDENTIALS_PATH -> response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThatThrownBy(() -> fixture.client().readCredentials())
                .isInstanceOf(VaultException.class)
                // the rejection the caller reports is the one it received, not the failure of the
                // question it asked about it
                .hasMessageContaining("HTTP 403");

        // a server that cannot answer a lookup issues no tokens either, so nothing was replayed
        assertThat(fixture.processor().requests(CREDENTIALS_PATH)).hasSize(1);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
    }

    @Test
    public void testRejectionOfAnAlreadyReplacedTokenIsReplayedWithTheCurrentOne()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(SECOND_TOKEN, 3600, true));
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);
        // the request was in flight while another thread replaced the token it carried: the one the
        // cache holds now is worth replaying with, and obtaining it costs neither a login nor a
        // question about a token nobody uses any more
        assertThat(fixture.tokenSupplier().tokenAfterRejection(FIRST_TOKEN)).contains(SECOND_TOKEN);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
        assertThat(fixture.processor().requests(LOOKUP_SELF_PATH)).isEmpty();
    }

    @Test
    public void testTokenReplacedByALoginIsRevokedOnShutdown()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            // a token that cannot be renewed is replaced by a login well before it expires
            case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60, false));
            case REVOKE_SELF_PATH -> noContent();
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(45, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);
        // the token the login replaced is not revoked there: the database leases read with it belong
        // to connections that are still open
        assertThat(fixture.processor().requests(REVOKE_SELF_PATH)).isEmpty();

        fixture.shutdown();

        List<String> revoked = fixture.processor().requests(REVOKE_SELF_PATH).stream()
                .map(request -> request.getHeader(HeaderName.of("X-Vault-Token")))
                .collect(toImmutableList());
        // the token in use first, then the one it replaced, which is still inside its lifetime
        assertThat(revoked).containsExactly(SECOND_TOKEN, FIRST_TOKEN);
    }

    @Test
    public void testTokenReplacedLongAgoIsNotRevokedOnShutdown()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60, false));
            case REVOKE_SELF_PATH -> noContent();
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(45, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);
        // past the lifetime of the first token, inside the one of the second
        ticker.increment(30, SECONDS);
        fixture.shutdown();

        // a token that is gone from the token store is not worth a request while the connector is
        // shutting down
        List<String> revoked = fixture.processor().requests(REVOKE_SELF_PATH).stream()
                .map(request -> request.getHeader(HeaderName.of("X-Vault-Token")))
                .collect(toImmutableList());
        assertThat(revoked).containsExactly(SECOND_TOKEN);
    }

    @Test
    public void testKubernetesLoginReadsTheStandardPathWhenNoFileIsConfigured()
    {
        // the path Kubernetes writes the token of a pod to. A catalog running in a pod names no
        // file, so a typo in that constant would only show up on a real cluster
        VaultConnectionConfig config = baseConfig()
                .setAuthMethod(KUBERNETES)
                .setKubernetesRole("trino-coordinator");
        Fixture fixture = fixture(config, new TestingTicker(), (request, _) -> {
            throw new AssertionError("the login must fail before any request, got " + request.getUri());
        });

        assertThatThrownBy(() -> fixture.tokenSupplier().get())
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Failed to read Kubernetes service account token file")
                .hasMessageContaining("/var/run/secrets/kubernetes.io/serviceaccount/token");
    }

    @Test
    public void testKubernetesLoginSendsTheProjectedServiceAccountToken(@TempDir Path tempDir)
            throws IOException
    {
        Path jwtFile = tempDir.resolve("service-account-token");
        Files.writeString(jwtFile, "first.jwt.value\n", UTF_8);
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        VaultConnectionConfig config = baseConfig()
                .setAuthMethod(KUBERNETES)
                .setKubernetesRole("trino-coordinator")
                .setKubernetesServiceAccountTokenFile(jwtFile.toFile());
        Fixture fixture = fixture(config, ticker, (request, _) -> switch (path(request)) {
            case KUBERNETES_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60, false));
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        // the kubelet rewrites a projected token in place well before it expires
        Files.writeString(jwtFile, "second.jwt.value\n", UTF_8);
        ticker.increment(45, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);

        List<Request> logs = fixture.processor().requests(KUBERNETES_LOGIN_PATH);
        assertThat(logs).hasSize(2);
        assertThat(logs.get(0).getHeader(HeaderName.of("X-Vault-Token"))).isNull();
        assertThat(body(logs.get(0)))
                .contains("\"role\" : \"trino-coordinator\"")
                .contains("\"jwt\" : \"first.jwt.value\"");
        assertThat(body(logs.get(1))).contains("\"jwt\" : \"second.jwt.value\"");
    }

    @Test
    public void testMissingServiceAccountTokenFileIsReported(@TempDir Path tempDir)
    {
        Path jwtFile = tempDir.resolve("service-account-token");
        VaultConnectionConfig config = baseConfig()
                .setAuthMethod(KUBERNETES)
                .setKubernetesRole("trino-coordinator")
                // the file exists when the catalog is created and is gone by the time it is read again
                .setKubernetesServiceAccountTokenFile(jwtFile.toFile());
        Fixture fixture = fixture(config, new TestingTicker(), (request, _) -> {
            throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThatThrownBy(() -> fixture.tokenSupplier().get())
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Failed to read Kubernetes service account token file")
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(REFUSED);
    }

    @Test
    public void testLoginResponseWithoutTokenIsReported()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok("{\"auth\": null, \"lease_duration\": 0}");
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThatThrownBy(() -> fixture.tokenSupplier().get())
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("response has no 'auth.client_token'")
                .hasMessageContaining("the AppRole method on mount 'approle'");
    }

    @Test
    public void testLoginIsRepeatedWhenTheServerDidNotServeIt()
    {
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            // the node the request reached is restarting, which is what a rolling restart of the
            // server looks like from here
            case APPROLE_LOGIN_PATH -> logins.getAndIncrement() == 0
                    ? response(HttpStatus.SERVICE_UNAVAILABLE, SEALED)
                    : ok(loginResponse(FIRST_TOKEN, 3600, true));
            case CREDENTIALS_PATH -> ok(CREDENTIALS_RESPONSE);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        // a single 503 on the login must not fail the creation of the catalog
        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);
        assertThat(fixture.processor().requests(CREDENTIALS_PATH).getFirst().getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(FIRST_TOKEN);
    }

    @Test
    public void testLoginIsRepeatedABoundedNumberOfTimes()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> response(HttpStatus.SERVICE_UNAVAILABLE, SEALED);
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThatThrownBy(() -> fixture.client().readCredentials())
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("HTTP 503")
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(UNAVAILABLE);
        // a server that is down does not turn one credential read into a login storm
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(3);
    }

    @Test
    public void testRenewSelfIsRepeatedBeforeFallingBackToALogin()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger renewals = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 60, true));
            case RENEW_SELF_PATH -> renewals.getAndIncrement() == 0
                    ? response(HttpStatus.SERVICE_UNAVAILABLE, SEALED)
                    : ok(loginResponse(FIRST_TOKEN, 60, true));
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(45, SECONDS);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);

        // the repeated renewal succeeded, so no second token was created in the storage backend
        assertThat(fixture.processor().requests(RENEW_SELF_PATH)).hasSize(2);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
    }

    @Test
    @Timeout(60)
    public void testATokenRejectedWhileItIsRenewedNeverReturnsToTheCache()
            throws Exception
    {
        CountDownLatch renewalStarted = new CountDownLatch(1);
        CountDownLatch renewalUnblocked = new CountDownLatch(1);
        CountDownLatch invalidationStarted = new CountDownLatch(1);
        AtomicInteger logins = new AtomicInteger();
        TestingTicker ticker = new TestingTicker();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(logins.getAndIncrement() == 0 ? FIRST_TOKEN : SECOND_TOKEN, 60, true));
            // the token we ask about was revoked on the server, which is why it was rejected
            case LOOKUP_SELF_PATH -> response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            // renew-self hands back the very same token, and the server answers only once the test
            // has had that token rejected
            case RENEW_SELF_PATH -> {
                renewalStarted.countDown();
                renewalUnblocked.await(30, SECONDS);
                yield ok(loginResponse(FIRST_TOKEN, 60, true));
            }
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        ticker.increment(45, SECONDS);
        Future<String> refresh = executor.submit(() -> fixture.tokenSupplier().get());
        assertThat(renewalStarted.await(30, SECONDS)).isTrue();

        AtomicReference<Thread> invalidating = new AtomicReference<>();
        Future<Optional<String>> replacement = executor.submit(() -> {
            invalidating.set(Thread.currentThread());
            invalidationStarted.countDown();
            return fixture.tokenSupplier().tokenAfterRejection(FIRST_TOKEN);
        });
        assertThat(invalidationStarted.await(30, SECONDS)).isTrue();
        awaitWaitingForTheRefresh(invalidating);
        renewalUnblocked.countDown();

        // the renewal lost the race, so it logged in instead of putting the rejected token back
        assertThat(replacement.get(30, SECONDS)).contains(SECOND_TOKEN);
        assertThat(refresh.get(30, SECONDS)).isNotEqualTo(FIRST_TOKEN);
        assertThat(fixture.tokenSupplier().get()).isEqualTo(SECOND_TOKEN);
        assertThat(fixture.processor().requests(RENEW_SELF_PATH)).hasSize(1);
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(2);
    }

    @Test
    public void testTokenIsRevokedOnShutdown()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 3600, true));
            case REVOKE_SELF_PATH -> noContent();
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        fixture.shutdown();

        Request revocation = fixture.processor().requests(REVOKE_SELF_PATH).getFirst();
        assertThat(revocation.getMethod()).isEqualTo("POST");
        assertThat(revocation.getUri()).isEqualTo(URI.create(ENDPOINT + REVOKE_SELF_PATH));
        assertThat(revocation.getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo(FIRST_TOKEN);

        // a stopped supplier logs in no more: a token issued now would never be revoked
        assertThatThrownBy(() -> fixture.tokenSupplier().get())
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("the AppRole method on mount 'approle'")
                .hasMessageContaining("no token is issued")
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(REFUSED);
        fixture.shutdown();
        assertThat(fixture.processor().requests(APPROLE_LOGIN_PATH)).hasSize(1);
        assertThat(fixture.processor().requests(REVOKE_SELF_PATH)).hasSize(1);
    }

    @Test
    public void testATokenSupersededWhileTheConnectorStopsIsRevokedAnyway()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse("hvs.CAESIToken" + logins.getAndIncrement(), 60, false));
            case REVOKE_SELF_PATH -> noContent();
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });
        LoginVaultTokenSupplier supplier = (LoginVaultTokenSupplier) fixture.tokenSupplier();

        assertThat(supplier.get()).isEqualTo("hvs.CAESIToken0");
        // past the refresh point of a token that cannot be renewed, so the next call logs in
        ticker.increment(45, SECONDS);
        // the connector is shut down in the few instructions between publishing the new token and
        // queueing the one it replaces: the shutdown drains a queue the replaced token is not in yet
        supplier.beforeSupersede = supplier::shutdown;

        assertThatThrownBy(supplier::get)
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("no token is issued");

        assertThat(supplier.supersededTokenCount())
                .as("tokens left waiting for a revocation nobody will send")
                .isZero();
        Set<String> revoked = fixture.processor().requests(REVOKE_SELF_PATH).stream()
                .map(request -> request.getHeader(HeaderName.of("X-Vault-Token")))
                .collect(toImmutableSet());
        assertThat(revoked)
                .as("both the token the login issued and the one it replaced")
                .containsExactlyInAnyOrder("hvs.CAESIToken0", "hvs.CAESIToken1");
    }

    @Test
    public void testSupersededTokensAreBounded()
    {
        TestingTicker ticker = new TestingTicker();
        AtomicInteger logins = new AtomicInteger();
        Fixture fixture = fixture(appRoleConfig(), ticker, (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse("hvs.CAESIToken" + logins.getAndIncrement(), 60, false));
            case REVOKE_SELF_PATH -> noContent();
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo("hvs.CAESIToken0");
        for (int generation = 1; generation <= MAX_SUPERSEDED_TOKENS + 4; generation++) {
            ticker.increment(45, SECONDS);
            assertThat(fixture.tokenSupplier().get()).isEqualTo("hvs.CAESIToken" + generation);
        }

        // a catalog that runs for weeks replaces its token again and again, and the ones that are
        // long expired must not pile up until it is shut down
        assertThat(((LoginVaultTokenSupplier) fixture.tokenSupplier()).supersededTokenCount()).isEqualTo(MAX_SUPERSEDED_TOKENS);

        fixture.shutdown();
        // all of them but the one replaced last outlived their lifetime, and a token that is gone
        // from the token store is not asked about while the connector is shutting down
        List<String> revoked = fixture.processor().requests(REVOKE_SELF_PATH).stream()
                .map(request -> request.getHeader(HeaderName.of("X-Vault-Token")))
                .collect(toImmutableList());
        assertThat(revoked).containsExactly(
                "hvs.CAESIToken" + (MAX_SUPERSEDED_TOKENS + 4),
                "hvs.CAESIToken" + (MAX_SUPERSEDED_TOKENS + 3));
    }

    @Test
    public void testFailedRevocationDoesNotFailShutdown()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> switch (path(request)) {
            case APPROLE_LOGIN_PATH -> ok(loginResponse(FIRST_TOKEN, 3600, true));
            case REVOKE_SELF_PATH -> response(HttpStatus.INTERNAL_SERVER_ERROR, "{\"errors\":[\"internal error\"]}");
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.tokenSupplier().get()).isEqualTo(FIRST_TOKEN);
        // the token dies at the end of its lifetime instead, and the rest of the connector still
        // shuts down
        assertThatCode(fixture::shutdown).doesNotThrowAnyException();
        // one attempt, no retry: a shutdown must not wait for a server that is down
        assertThat(fixture.processor().requests(REVOKE_SELF_PATH)).hasSize(1);
    }

    @Test
    public void testNothingIsRevokedWhenNoTokenWasIssued()
    {
        Fixture fixture = fixture(appRoleConfig(), new TestingTicker(), (request, _) -> {
            throw new AssertionError("unexpected request " + request.getUri());
        });

        // a catalog that never resolved credentials has nothing to revoke
        assertThatCode(fixture::shutdown).doesNotThrowAnyException();
        assertThat(fixture.processor().requests()).isEmpty();
    }

    @Test
    public void testRejectedTokenFileIsReadOnceForTheReplay(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, "first-token\n", UTF_8);
        AtomicInteger reads = new AtomicInteger();
        Fixture fixture = fileTokenFixture(tokenFile, (request, _) -> switch (path(request)) {
            case CREDENTIALS_PATH -> {
                if (reads.getAndIncrement() > 0) {
                    yield ok(CREDENTIALS_RESPONSE);
                }
                // an agent sidecar rewrote the file, which is why the token in flight was rejected
                Files.writeString(tokenFile, "rotated-token\n", UTF_8);
                yield response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            }
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThat(fixture.client().readCredentials().username()).isEqualTo(USER);

        List<Request> credentialRequests = fixture.processor().requests(CREDENTIALS_PATH);
        assertThat(credentialRequests).hasSize(2);
        assertThat(credentialRequests.get(0).getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo("first-token");
        // the replay carries the token the supplier read when it decided to replay, not the result
        // of a second read of the same file
        assertThat(credentialRequests.get(1).getHeader(HeaderName.of("X-Vault-Token"))).isEqualTo("rotated-token");
    }

    @Test
    public void testTokenFileRemovedWhileTheTokenIsRejectedKeepsTheRejection(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, "first-token\n", UTF_8);
        Fixture fixture = fileTokenFixture(tokenFile, (request, _) -> switch (path(request)) {
            case CREDENTIALS_PATH -> {
                // the secret is unmounted while the token it held is being rejected
                Files.delete(tokenFile);
                yield response(HttpStatus.FORBIDDEN, PERMISSION_DENIED);
            }
            default -> throw new AssertionError("unexpected request " + request.getUri());
        });

        assertThatThrownBy(() -> fixture.client().readCredentials())
                .isInstanceOf(VaultException.class)
                // the rejection retains its status, and it is not replaced by
                // the failure to read a file that is gone
                .hasMessageContaining("HTTP 403")
                .satisfies(failure -> {
                    assertThat(failure.getSuppressed()).hasSize(1);
                    assertThat(failure.getSuppressed()[0]).hasMessageContaining("Failed to read Vault token file");
                });
        // nothing was replayed, there was no token to replay with
        assertThat(fixture.processor().requests(CREDENTIALS_PATH)).hasSize(1);
    }

    /**
     * Waits until the thread that is invalidating the token has dropped it from the cache and is
     * waiting for the refresh that is already in flight. Dropping takes no lock, so a thread that is
     * blocked is a thread that is past it.
     */
    private static void awaitWaitingForTheRefresh(AtomicReference<Thread> invalidating)
            throws InterruptedException
    {
        long deadline = System.nanoTime() + SECONDS.toNanos(30);
        // the thread is queued on the monitor of the refresh in flight, which is held by a thread that
        // is parked, so it stays BLOCKED. Every other monitor on its way there - the list inside the
        // recording processor, the class initialisation of the JSON and retry machinery - is held for
        // microseconds, so a single sample of BLOCKED proves nothing and a run of them does
        int blockedSamples = 0;
        while (blockedSamples < 50) {
            if (System.nanoTime() - deadline >= 0) {
                throw new AssertionError("the invalidating thread never waited for the refresh in flight");
            }
            blockedSamples = invalidating.get().getState() == Thread.State.BLOCKED ? blockedSamples + 1 : 0;
            MILLISECONDS.sleep(1);
        }
    }

    private static VaultConnectionConfig baseConfig()
    {
        return new VaultConnectionConfig()
                .setEndpoint(ENDPOINT);
    }

    private static VaultConnectionConfig appRoleConfig()
    {
        return baseConfig()
                .setAuthMethod(APPROLE)
                .setAppRoleRoleId(ROLE_ID)
                .setAppRoleSecretId(SECRET_ID);
    }

    private static Fixture fixture(VaultConnectionConfig config, TestingTicker ticker, RequestHandler handler)
    {
        RecordingProcessor processor = new RecordingProcessor(handler);
        // retries must not sleep in a unit test
        VaultHttp http = new VaultHttp(new TestingHttpClient(processor), config, Duration.ZERO);
        VaultLoginMethod loginMethod = switch (config.getAuthMethod()) {
            case TOKEN -> throw new AssertionError("a configured token needs no login method");
            case APPROLE -> new AppRoleLoginMethod(http, config);
            case KUBERNETES -> new KubernetesLoginMethod(http, config);
        };
        LoginVaultTokenSupplier tokenSupplier = new LoginVaultTokenSupplier(loginMethod, http, ticker);
        return new Fixture(processor, tokenSupplier, new VaultClient(new VaultSession(http, tokenSupplier), new VaultDatabaseConfig().setRole("trino-dynamic")));
    }

    /**
     * A catalog whose token comes from {@code vault.token-file}, the only supplier that can fail
     * while producing the token a rejected request would be replayed with.
     */
    private static Fixture fileTokenFixture(Path tokenFile, RequestHandler handler)
    {
        VaultConnectionConfig config = baseConfig().setTokenFile(tokenFile.toFile());
        RecordingProcessor processor = new RecordingProcessor(handler);
        VaultHttp http = new VaultHttp(new TestingHttpClient(processor), config, Duration.ZERO);
        VaultTokenSupplier tokenSupplier = new FileVaultTokenSupplier(tokenFile);
        return new Fixture(processor, tokenSupplier, new VaultClient(new VaultSession(http, tokenSupplier), new VaultDatabaseConfig().setRole("trino-dynamic")));
    }

    private static String loginResponse(String clientToken, long leaseDuration, boolean renewable)
    {
        return format(
                """
                {
                  "lease_id": "",
                  "lease_duration": 0,
                  "renewable": false,
                  "auth": {"client_token": "%s", "lease_duration": %s, "renewable": %s, "token_type": "service"}
                }
                """,
                clientToken,
                leaseDuration,
                renewable);
    }

    private static String batchLoginResponse(String clientToken, long leaseDuration)
    {
        return format(
                """
                {
                  "auth": {"client_token": "%s", "lease_duration": %s, "renewable": false, "token_type": "batch"}
                }
                """,
                clientToken,
                leaseDuration);
    }

    private static String path(Request request)
    {
        return request.getUri().getPath();
    }

    private static String body(Request request)
    {
        return new String(((StaticBodyGenerator) request.getBodyGenerator()).getBody(), UTF_8);
    }

    private static Response ok(String body)
    {
        return response(HttpStatus.OK, body);
    }

    private static Response noContent()
    {
        return response(HttpStatus.NO_CONTENT, "");
    }

    private static Response response(HttpStatus status, String body)
    {
        return TestingResponse.mockResponse(status, MediaType.JSON_UTF_8, body);
    }

    private record Fixture(RecordingProcessor processor, VaultTokenSupplier tokenSupplier, VaultClient client)
    {
        /**
         * Stops the supplier the way the life cycle manager does.
         */
        private void shutdown()
        {
            ((LoginVaultTokenSupplier) tokenSupplier).shutdown();
        }
    }

    private interface RequestHandler
    {
        Response apply(Request request, int attempt)
                throws Exception;
    }

    private static final class RecordingProcessor
            implements TestingHttpClient.Processor
    {
        private final List<Request> requests = new CopyOnWriteArrayList<>();
        private final RequestHandler handler;

        private RecordingProcessor(RequestHandler handler)
        {
            this.handler = handler;
        }

        @Override
        public Response handle(Request request)
                throws Exception
        {
            requests.add(request);
            return handler.apply(request, requests.size() - 1);
        }

        private List<Request> requests()
        {
            return requests;
        }

        private List<Request> requests(String path)
        {
            return requests.stream()
                    .filter(request -> path(request).equals(path))
                    .collect(toImmutableList());
        }
    }
}
