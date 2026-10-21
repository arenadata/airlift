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
package io.airlift.vault.http;

import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.testing.TestingHttpClient;
import io.airlift.http.client.testing.TestingResponse;
import io.airlift.json.JsonCodec;
import io.airlift.vault.VaultClient;
import io.airlift.vault.VaultSession;
import io.airlift.vault.auth.StaticVaultTokenSupplier;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.config.VaultDatabaseConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import static com.google.common.base.Throwables.getStackTraceAsString;
import static com.google.common.net.MediaType.JSON_UTF_8;
import static io.airlift.json.JsonCodec.mapJsonCodec;
import static io.airlift.vault.VaultException.Category.REFUSED;
import static io.airlift.vault.VaultException.Category.UNAVAILABLE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

@Isolated("Changes Vault logger levels to verify complete diagnostics")
class TestVaultHttpDiagnostics
{
    private static final URI ENDPOINT = URI.create("http://vault.invalid:8200");
    private static final String SECRET = "UNQUOTED_REMOTE_SECRET_718349";
    private static final String OPERATION = "Failed to read credentials for role 'test' from Vault";
    private static final JsonCodec<Map<String, Object>> CODEC = mapJsonCodec(String.class, Object.class);

    private static final List<Operation> OPERATIONS = List.of(
            new Operation(http -> http.get(ENDPOINT, Optional.of(SECRET), CODEC, OPERATION), 3, 3, true),
            new Operation(http -> http.getSecret(ENDPOINT, Optional.of(SECRET), CODEC, OPERATION), 3, 3, true),
            new Operation(http -> http.getCreatingSecret(ENDPOINT, Optional.of(SECRET), CODEC, OPERATION), 1, 3, true),
            new Operation(http -> http.post(ENDPOINT, Optional.of(SECRET), Map.of("secret", SECRET), CODEC, OPERATION), 3, 3, true),
            new Operation(http -> http.postSecret(ENDPOINT, Optional.of(SECRET), Map.of("secret", SECRET), CODEC, OPERATION), 3, 3, true),
            new Operation(http -> http.postCreatingSecret(ENDPOINT, Optional.empty(), Map.of("secret", SECRET), CODEC, OPERATION), 1, 3, true),
            new Operation(http -> http.postExpectingNoContent(ENDPOINT, SECRET, Map.of(), OPERATION), 1, 1, false),
            new Operation(http -> http.postSecretExpectingNoContent(ENDPOINT, SECRET, Map.of(), OPERATION), 1, 1, false));

    @Test
    void testRemoteErrorBodiesNeverReachDiagnostics()
    {
        try (LogCapture logs = new LogCapture()) {
            for (int status : List.of(400, 500)) {
                for (Operation operation : OPERATIONS) {
                    AtomicInteger attempts = new AtomicInteger();
                    try (TestingHttpClient client = new TestingHttpClient(_ -> {
                        attempts.incrementAndGet();
                        return response(status, "{\"errors\":[\"password=" + SECRET + "\",\"" + SECRET + "\"]}");
                    })) {
                        VaultHttpException failure = failure(operation, http(client));
                        assertThat(failure.getMessage()).isEqualTo(OPERATION + ": HTTP " + status);
                        assertThat(failure.statusCode()).isEqualTo(status);
                        assertThat(failure.category()).isEqualTo(status == 500 ? UNAVAILABLE : REFUSED);
                        assertThat(attempts).hasValue(status == 500 ? operation.serverFailureAttempts() : 1);
                    }
                }
            }
            logs.assertSafe();
        }
    }

    @Test
    void testTransportCausesAreUsedOnlyForRetryClassification()
    {
        try (LogCapture logs = new LogCapture()) {
            for (Operation operation : OPERATIONS) {
                for (boolean connectionRefused : List.of(true, false)) {
                    Exception transportFailure = connectionRefused ? new ConnectException(SECRET) : new SocketTimeoutException(SECRET);
                    transportFailure.initCause(new IllegalArgumentException("cause " + SECRET));
                    transportFailure.addSuppressed(new IllegalStateException("suppressed " + SECRET));
                    AtomicInteger attempts = new AtomicInteger();
                    try (TestingHttpClient client = new TestingHttpClient(_ -> {
                        attempts.incrementAndGet();
                        throw transportFailure;
                    })) {
                        VaultHttpException failure = failure(operation, http(client));
                        assertThat(failure.getMessage()).isEqualTo(OPERATION);
                        assertThat(failure.statusCode()).isZero();
                        assertThat(failure.httpStatusCode()).isEmpty();
                        assertThat(failure.category()).isEqualTo(UNAVAILABLE);
                        assertThat(attempts).hasValue(connectionRefused ? operation.connectionFailureAttempts() : operation.serverFailureAttempts());
                    }
                }
            }
            logs.assertSafe();
        }
    }

    @Test
    void testMalformedSuccessRetainsOnlyTheSafeParseReason()
    {
        for (Operation operation : OPERATIONS) {
            if (!operation.expectsJson()) {
                continue;
            }
            AtomicInteger attempts = new AtomicInteger();
            try (TestingHttpClient client = new TestingHttpClient(_ -> {
                attempts.incrementAndGet();
                return response(200, "{\"data\":\"" + SECRET + "\"");
            })) {
                VaultHttpException failure = failure(operation, http(client));
                assertThat(failure.getMessage()).isEqualTo(OPERATION + ": response is not valid JSON of the expected shape");
                assertThat(failure.statusCode()).isEqualTo(200);
                assertThat(failure.category()).isEqualTo(REFUSED);
                assertThat(attempts).hasValue(1);
            }
        }
    }

    @Test
    void testLeaseRenewalAndRevocationLogsHideRemoteContent()
    {
        try (LogCapture logs = new LogCapture()) {
            for (int status : List.of(400, 500)) {
                try (TestingHttpClient client = new TestingHttpClient(_ -> response(status, "{\"errors\":[\"" + SECRET + "\"]}"));
                        VaultSession session = new VaultSession(http(client), new StaticVaultTokenSupplier(SECRET))) {
                    VaultClient database = new VaultClient(session, new VaultDatabaseConfig().setRole("test"));
                    if (status == 400) {
                        assertThat(database.renewLease(SECRET)).isEmpty();
                    }
                    else {
                        assertThatThrownBy(() -> database.renewLease(SECRET))
                                .isInstanceOf(VaultHttpException.class)
                                .satisfies(TestVaultHttpDiagnostics::assertSafe);
                    }
                    assertThat(database.revokeLease(SECRET)).isFalse();
                }
            }
            try (TestingHttpClient client = new TestingHttpClient(_ -> { throw new ConnectException(SECRET); });
                    VaultSession session = new VaultSession(http(client), new StaticVaultTokenSupplier(SECRET))) {
                VaultClient database = new VaultClient(session, new VaultDatabaseConfig().setRole("test"));
                assertThat(database.revokeLease(SECRET)).isFalse();
            }
            assertThat(logs.records).anySatisfy(record -> assertThat(record.getThrown()).isNotNull());
            logs.assertSafe();
        }
    }

    private static VaultHttpException failure(Operation operation, VaultHttp http)
    {
        Throwable failure = catchThrowable(() -> operation.exchange().run(http));
        assertThat(failure).isInstanceOf(VaultHttpException.class);
        assertSafe(failure);
        return (VaultHttpException) failure;
    }

    private static void assertSafe(Throwable failure)
    {
        assertThat(failure).hasNoCause().hasMessageNotContaining(SECRET);
        assertThat(failure.getSuppressed()).isEmpty();
        assertThat(getStackTraceAsString(failure)).doesNotContain(SECRET);
    }

    private static VaultHttp http(TestingHttpClient client)
    {
        return new VaultHttp(client, new VaultConnectionConfig().setEndpoint(ENDPOINT), Duration.ZERO);
    }

    private static TestingResponse response(int status, String body)
    {
        return new TestingResponse(HttpStatus.OK, TestingResponse.contentType(JSON_UTF_8), body.getBytes(UTF_8))
        {
            @Override
            public int getStatusCode()
            {
                return status;
            }
        };
    }

    private record Operation(Exchange exchange, int serverFailureAttempts, int connectionFailureAttempts, boolean expectsJson) {}

    private interface Exchange
    {
        void run(VaultHttp http);
    }

    private static final class LogCapture
            implements AutoCloseable
    {
        private final List<LogRecord> records = new CopyOnWriteArrayList<>();
        private final Logger logger = Logger.getLogger("io.airlift.vault");
        private final Level previousLevel = logger.getLevel();
        private final Handler handler = new Handler()
        {
            @Override
            public void publish(LogRecord record)
            {
                records.add(record);
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };

        private LogCapture()
        {
            logger.addHandler(handler);
            logger.setLevel(Level.FINE);
        }

        private void assertSafe()
        {
            SimpleFormatter formatter = new SimpleFormatter();
            assertThat(records).isNotEmpty().allSatisfy(record -> assertThat(formatter.format(record)).doesNotContain(SECRET));
        }

        @Override
        public void close()
        {
            logger.removeHandler(handler);
            logger.setLevel(previousLevel);
        }
    }
}
