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

import com.google.common.collect.ImmutableMap;
import com.google.common.net.MediaType;
import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.Request;
import io.airlift.http.client.Response;
import io.airlift.http.client.testing.TestingHttpClient;
import io.airlift.http.client.testing.TestingResponse;
import io.airlift.json.JsonCodec;
import io.airlift.vault.VaultException;
import io.airlift.vault.VaultException.Category;
import io.airlift.vault.config.VaultConnectionConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.stream.IntStream;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static io.airlift.json.JsonCodec.mapJsonCodec;
import static io.airlift.vault.VaultException.Category.REFUSED;
import static io.airlift.vault.VaultException.Category.UNAVAILABLE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * The backoff of {@link VaultHttp} and the classification behind it: what is worth another attempt,
 * what may be repeated even when the server creates a secret, and how long a caller waits before the
 * transport gives up.
 * <p>
 * Every other test builds the transport with a zero delay, which leaves the backoff unexercised.
 * Here it is the subject, so it is real, and only the tests that measure it pay for it.
 */
final class TestVaultHttpRetries
{
    private static final URI ENDPOINT = URI.create("http://openbao.invalid:8200");
    private static final String TOKEN = "trino-root-token";
    private static final String ROLE = "trino-dynamic";
    private static final String CREDENTIALS_PATH = "/v1/database/creds/" + ROLE;
    private static final String REVOKE_SELF_PATH = "/v1/auth/token/revoke-self";
    private static final String OPERATION = "Failed to read credentials for role '" + ROLE + "' from Vault at " + ENDPOINT;
    private static final String REVOKE_OPERATION = "Failed to revoke the token of Vault at " + ENDPOINT;

    /**
     * The status a performance standby answers a request it cannot serve itself with. Neither
     * {@link HttpStatus} nor any other enum has a constant for it, which is why the whole
     * classification here is written in status codes.
     */
    private static final int PERFORMANCE_STANDBY = 473;

    private static final JsonCodec<Map<String, Object>> RESPONSE_CODEC = mapJsonCodec(String.class, Object.class);

    private static final String ERROR_BODY = "{\"errors\":[\"the request failed\"]}";

    private static final String CREDENTIALS_RESPONSE =
            """
            {
              "lease_id": "database/creds/trino-dynamic/tCq1V0hZ3Zc2u1jH1n1cQxWl",
              "renewable": false,
              "lease_duration": 3600,
              "data": {"username": "v-token-trino-dy-x9Kq3Yy2Xn8LQ0-1774000000", "password": "A1a-8s0Ez7fSb7yqM2Rk"}
            }
            """;

    /**
     * The base delay the tests that measure the backoff build the transport with. Doubling it and
     * adding the twenty percent of jitter puts the first delay in [400, 600] ms and the second in
     * [800, 1200] ms: the two bands do not overlap, so an assertion can tell them apart without
     * knowing the random draw, and three attempts cost under two seconds.
     */
    private static final Duration MEASURED_BASE_DELAY = Duration.ofMillis(500);

    /**
     * A read of a static role: the server hands back a password it already stores, so nothing is
     * created and any temporary failure is worth repeating.
     */
    private static final Exchange READ = http -> http.get(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION);

    /**
     * A read of a dynamic role: serving it makes the server create a database account, so only a
     * failure that proves the server did not serve the request may be repeated.
     */
    private static final Exchange READ_CREATING_SECRET = http ->
            http.getCreatingSecret(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION);

    @Test
    @Timeout(60)
    void testTheDelayBetweenAttemptsGrows()
    {
        RecordingProcessor processor = new RecordingProcessor(_ -> response(503, ERROR_BODY));
        VaultHttp http = http(processor, MEASURED_BASE_DELAY);

        assertThatThrownBy(() -> READ.run(http)).isInstanceOf(VaultException.class);

        // three attempts leave two gaps, and each gap is the delay plus the time the fake server took,
        // which is nothing here. A fixed delay would make the second gap the size of the first: it is
        // the exponential backoff that puts it past the band the first one can fall into
        List<Long> delayMillis = processor.delayMillis();
        assertThat(delayMillis).hasSize(2);
        assertThat(delayMillis.get(0))
                .as("the first delay, from a base of %s ms", MEASURED_BASE_DELAY.toMillis())
                .isGreaterThanOrEqualTo(380);
        assertThat(delayMillis.get(1))
                .as("the second delay, doubled")
                .isGreaterThanOrEqualTo(780);
        assertThat(delayMillis.get(1)).isGreaterThan(delayMillis.get(0));
    }

    @Test
    void testThrottlingAndServerFailuresAreRepeated()
    {
        // what the server itself reports as temporary: the rate limiter and every 5xx
        assertAttempts(READ, 429, 3, UNAVAILABLE);
        assertAttempts(READ, 500, 3, UNAVAILABLE);
        assertAttempts(READ, 502, 3, UNAVAILABLE);
        assertAttempts(READ, 503, 3, UNAVAILABLE);
    }

    @Test
    void testARefusalIsNotRepeated()
    {
        // a malformed request, a token without the policy and an unknown role are configuration and
        // permission problems: the second attempt would be answered exactly like the first
        assertAttempts(READ, 400, 1, REFUSED);
        assertAttempts(READ, 403, 1, REFUSED);
        assertAttempts(READ, 404, 1, REFUSED);
    }

    @Test
    void testAStandbyNodeIsRepeatedByBothPolicies()
    {
        // 473 is what a performance standby answers with, and the transport reads it as a request the
        // server did not serve rather than as one whose outcome is unknown: unlike a 500, it is
        // repeated even where serving it would have created a database account
        assertAttempts(READ, PERFORMANCE_STANDBY, 3, UNAVAILABLE);
        assertAttempts(READ_CREATING_SECRET, PERFORMANCE_STANDBY, 3, UNAVAILABLE);
        assertAttempts(READ_CREATING_SECRET, 500, 1, UNAVAILABLE);
    }

    @Test
    void testTheAnswerOfTheAttemptThatSucceededIsReturned()
    {
        RecordingProcessor processor = new RecordingProcessor(attempt -> attempt == 0
                ? response(429, ERROR_BODY)
                : response(200, CREDENTIALS_RESPONSE));
        VaultHttp http = http(processor, Duration.ZERO);

        // a repeated request must hand the caller the body of the attempt that worked, not the failure
        // it started with
        Map<String, Object> credentials = http.get(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION);
        assertThat(credentials).containsKey("data");
        assertThat(processor.requests(CREDENTIALS_PATH)).hasSize(2);
    }

    @Test
    void testARequestThatNeverReachedTheServerIsRepeated()
    {
        RecordingProcessor processor = new RecordingProcessor(_ -> {
            throw new ConnectException("connection refused");
        });
        VaultHttp http = http(processor, Duration.ZERO);

        Throwable thrown = catchThrowable(() -> READ.run(http));
        assertThat(thrown).isInstanceOf(VaultHttpException.class);
        VaultHttpException failure = (VaultHttpException) thrown;
        // no status at all, which is what tells this failure from a 503 the server did answer
        assertThat(failure.statusCode()).isEqualTo(0);
        assertThat(failure.category()).isEqualTo(UNAVAILABLE);
        assertThat(processor.requests(CREDENTIALS_PATH)).hasSize(3);
    }

    @Test
    void testAnUnknownOutcomeIsRepeatedOnlyWhereItCostsNothing()
    {
        // a read timeout leaves the outcome unknown: the server may have created the account and
        // answered after the client stopped listening, so the read of a dynamic role gives up at once
        assertAttemptsAfter(new SocketTimeoutException("timed out"), READ, 3);
        assertAttemptsAfter(new SocketTimeoutException("timed out"), READ_CREATING_SECRET, 1);
        // a connection that never opened proves the server saw nothing, so even that read is repeated
        assertAttemptsAfter(new ConnectException("connection refused"), READ_CREATING_SECRET, 3);
    }

    @Test
    void testAResponseThatIsNotTheExpectedJsonIsNotRepeated()
    {
        // the error page of a proxy standing in front of the server, served with a 200
        RecordingProcessor processor = new RecordingProcessor(_ -> response(200, "<html>Bad gateway</html>"));
        VaultHttp http = http(processor, Duration.ZERO);

        assertThatThrownBy(() -> READ.run(http))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("response is not valid JSON of the expected shape")
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(REFUSED);
        // repeating it would produce the same body, so the answer is a refusal and comes at once
        assertThat(processor.requests(CREDENTIALS_PATH)).hasSize(1);
    }

    @Test
    void testARevocationIsNeverRepeated()
    {
        RecordingProcessor processor = new RecordingProcessor(_ -> response(503, ERROR_BODY));
        VaultHttp http = http(processor, Duration.ZERO);
        URI revokeSelf = http.uri("auth", "token", "revoke-self");

        assertThatThrownBy(() -> http.postExpectingNoContent(revokeSelf, TOKEN, ImmutableMap.of(), REVOKE_OPERATION))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("HTTP 503");
        // a revocation runs while the connector is shutting down, where waiting for a server that
        // stopped answering costs more than the token that expires on its own anyway
        assertThat(processor.requests(REVOKE_SELF_PATH)).hasSize(1);
    }

    @Test
    @Timeout(180)
    void testTheTotalRetryDurationIsBounded()
    {
        // The same 503 is repeated three times when it comes back at once, so what stops the second
        // attempt here is the thirty seconds of MAX_RETRY_DURATION rather than the classification.
        // The wait is real: the bound is a constant of VaultHttp and Failsafe measures it against the
        // system clock, so no injected delay can make this test cheaper than the bound it pins down.
        RecordingProcessor processor = new RecordingProcessor(_ -> {
            SECONDS.sleep(31);
            return response(503, ERROR_BODY);
        });
        VaultHttp http = http(processor, MEASURED_BASE_DELAY);

        assertThatThrownBy(() -> READ.run(http))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("HTTP 503");
        assertThat(processor.requests(CREDENTIALS_PATH))
                .as("an attempt that outlived the bound leaves no room for a second one")
                .hasSize(1);
    }

    /**
     * How often a failure of one status is repeated, and the code the caller is finally told.
     */
    private static void assertAttempts(Exchange exchange, int statusCode, int expectedAttempts, Category expectedErrorCode)
    {
        RecordingProcessor processor = new RecordingProcessor(_ -> response(statusCode, ERROR_BODY));
        // counting attempts needs no backoff, and a test that waits for one is a test nobody runs
        VaultHttp http = http(processor, Duration.ZERO);

        assertThatThrownBy(() -> exchange.run(http))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("HTTP " + statusCode)
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(expectedErrorCode);
        assertThat(processor.requests(CREDENTIALS_PATH))
                .as("attempts of HTTP %s", statusCode)
                .hasSize(expectedAttempts);
    }

    /**
     * How often a request that produced no response at all is repeated. What the client throws is what
     * the transport has to classify: nothing about it says whether the server acted on the request.
     */
    private static void assertAttemptsAfter(Exception failure, Exchange exchange, int expectedAttempts)
    {
        RecordingProcessor processor = new RecordingProcessor(_ -> {
            throw failure;
        });
        VaultHttp http = http(processor, Duration.ZERO);

        assertThatThrownBy(() -> exchange.run(http)).isInstanceOf(VaultException.class);
        assertThat(processor.requests(CREDENTIALS_PATH))
                .as("attempts after %s", failure.getClass().getSimpleName())
                .hasSize(expectedAttempts);
    }

    @Test
    void testAGeneratedPasswordInARefusedStatementIsNotReported()
    {
        // what MySQL and MariaDB answer when the creation_statements of a role are wrong: the server
        // echoes the statement it tried to run, with the password it had just generated substituted
        // into it, and the quoted literal carries a quote of its own
        String body =
                """
                {"errors":["1 error occurred: * Error 1064 (42000): You have an error in your SQL syntax near \
                'IDENTIFIED BY 'A1a-Zx9QsecretPW'' at line 1"]}""";
        RecordingProcessor processor = new RecordingProcessor(_ -> response(400, body));
        VaultHttp http = http(processor, Duration.ZERO);

        assertThatThrownBy(() -> http.getCreatingSecret(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION))
                .isInstanceOf(VaultException.class)
                // pairing quotes left to right used to leave the password between two redactions
                .hasMessageNotContaining("A1a-Zx9QsecretPW")
                .hasMessageContaining("HTTP 400");
    }

    @Test
    void testAPasswordAfterAQuoteInsideTheDiagnosticIsNotReported()
    {
        // the PostgreSQL shape of the same accident: a quote inside the diagnostic text, then the
        // password in a literal of its own
        String body =
                """
                {"errors":["syntax error at or near \"'\" in CREATE ROLE v-token-trino WITH PASSWORD 'A1a-secret'"]}""";
        RecordingProcessor processor = new RecordingProcessor(_ -> response(400, body));
        VaultHttp http = http(processor, Duration.ZERO);

        assertThatThrownBy(() -> http.getCreatingSecret(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION))
                .isInstanceOf(VaultException.class)
                .hasMessageNotContaining("A1a-secret");
    }

    @Test
    void testRefusalRetainsLocalContextAndHttpStatus()
    {
        // Remote error text has no reliable distinction between a diagnostic and a secret.
        // Keep the local operation and status so an operator can identify the refused request.
        RecordingProcessor processor = new RecordingProcessor(_ -> response(403,
                """
                {"errors":["permission denied"]}"""));
        VaultHttp http = http(processor, Duration.ZERO);

        assertThatThrownBy(() -> http.getCreatingSecret(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION))
                .hasMessage(OPERATION + ": HTTP 403")
                .hasNoCause();
    }

    private static VaultHttp http(RecordingProcessor processor, Duration retryBaseDelay)
    {
        // the transport reads the endpoint and the namespace off the config and nothing else
        VaultConnectionConfig config = new VaultConnectionConfig().setEndpoint(ENDPOINT);
        return new VaultHttp(new TestingHttpClient(processor), config, retryBaseDelay);
    }

    @Test
    void testSecretAndAuthenticationFailuresDoNotExposeResponseOrTransportContent()
    {
        String sentinel = "unquoted-secret-sentinel";
        List<LogRecord> records = new CopyOnWriteArrayList<>();
        java.util.logging.Logger logger = java.util.logging.Logger.getLogger(VaultHttp.class.getName());
        Level previousLevel = logger.getLevel();
        Handler handler = new Handler()
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
        logger.addHandler(handler);
        logger.setLevel(Level.FINE);
        try {
            for (Exchange exchange : List.<Exchange>of(
                    http -> http.getSecret(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION),
                    http -> http.postSecret(credentialsUri(http), Optional.of(TOKEN), Map.of(), RESPONSE_CODEC, OPERATION),
                    http -> http.postCreatingSecret(credentialsUri(http), Optional.empty(), Map.of(), RESPONSE_CODEC, OPERATION),
                    http -> http.postSecretExpectingNoContent(credentialsUri(http), TOKEN, Map.of(), OPERATION))) {
                VaultHttp http = http(new RecordingProcessor(_ -> response(503, "{\"errors\":[\"" + sentinel + "\"]}")), Duration.ZERO);
                assertThatThrownBy(() -> exchange.run(http))
                        .isInstanceOf(VaultHttpException.class)
                        .hasMessageContaining("HTTP 503")
                        .hasMessageNotContaining(sentinel)
                        .hasNoCause();
            }
            RecordingProcessor processor = new RecordingProcessor(_ -> { throw new ConnectException(sentinel); });
            VaultHttp http = http(processor, Duration.ZERO);
            assertThatThrownBy(() -> http.postCreatingSecret(credentialsUri(http), Optional.empty(), Map.of(), RESPONSE_CODEC, OPERATION))
                    .hasMessageNotContaining(sentinel)
                    .hasNoCause();
            assertThat(processor.requests(CREDENTIALS_PATH)).hasSize(3);
            VaultHttp malformed = http(new RecordingProcessor(_ -> response(200, sentinel)), Duration.ZERO);
            assertThatThrownBy(() -> malformed.getSecret(credentialsUri(malformed), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION))
                    .hasMessageNotContaining(sentinel)
                    .hasNoCause();
            assertThat(records).isNotEmpty().allSatisfy(record -> {
                assertThat(record.getMessage()).doesNotContain(sentinel);
                assertThat(record.getThrown()).isNull();
            });
        }
        finally {
            logger.removeHandler(handler);
            logger.setLevel(previousLevel);
        }
    }

    @Test
    void testSecretFailureWithMalformedErrorEnvelope()
    {
        for (int status : List.of(403, 500)) {
            for (String body : List.of("null", "{}", "{\"errors\":null}", "{\"errors\":[null]}", "{\"errors\":\"unquoted-secret-sentinel\"}")) {
                RecordingProcessor processor = new RecordingProcessor(_ -> response(status, body));
                VaultHttp http = http(processor, Duration.ZERO);
                assertThatThrownBy(() -> http.getSecret(credentialsUri(http), Optional.of(TOKEN), RESPONSE_CODEC, OPERATION))
                        .isInstanceOf(VaultHttpException.class)
                        .hasMessageContaining("HTTP " + status)
                        .hasMessageNotContaining("unquoted-secret-sentinel")
                        .hasNoCause()
                        .satisfies(failure -> assertThat(((VaultHttpException) failure).category()).isEqualTo(status == 500 ? UNAVAILABLE : REFUSED));
                assertThat(processor.requests(CREDENTIALS_PATH)).hasSize(status == 500 ? 3 : 1);
            }
        }
    }

    private static URI credentialsUri(VaultHttp http)
    {
        return http.uri("database", "creds", ROLE);
    }

    private static String path(Request request)
    {
        return request.getUri().getPath();
    }

    /**
     * A response with a status of its own rather than one of the {@link HttpStatus} constants:
     * {@code 473} has none, and the classification under test is written in status codes.
     */
    private static Response response(int statusCode, String body)
    {
        return new TestingResponse(HttpStatus.OK, TestingResponse.contentType(MediaType.JSON_UTF_8), body.getBytes(UTF_8))
        {
            @Override
            public int getStatusCode()
            {
                return statusCode;
            }
        };
    }

    /**
     * One call into the transport, so that a test can say which of the two retry policies it exercises.
     */
    private interface Exchange
    {
        void run(VaultHttp http);
    }

    private interface ResponseFactory
    {
        Response apply(int attempt)
                throws Exception;
    }

    private static final class RecordingProcessor
            implements TestingHttpClient.Processor
    {
        private final List<Request> requests = new CopyOnWriteArrayList<>();
        private final List<Long> attemptNanos = new CopyOnWriteArrayList<>();
        private final ResponseFactory factory;

        private RecordingProcessor(ResponseFactory factory)
        {
            this.factory = factory;
        }

        @Override
        public Response handle(Request request)
                throws Exception
        {
            requests.add(request);
            attemptNanos.add(System.nanoTime());
            return factory.apply(requests.size() - 1);
        }

        private List<Request> requests(String path)
        {
            return requests.stream()
                    .filter(request -> path(request).equals(path))
                    .collect(toImmutableList());
        }

        /**
         * Milliseconds between the starts of consecutive attempts, which is the delay the transport
         * waited plus the time the fake server spent answering. Every value is therefore an upper
         * bound of the delay, and only assertions that grow with it are safe to make.
         */
        private List<Long> delayMillis()
        {
            return IntStream.range(1, attemptNanos.size())
                    .mapToObj(index -> NANOSECONDS.toMillis(attemptNanos.get(index) - attemptNanos.get(index - 1)))
                    .collect(toImmutableList());
        }
    }
}
