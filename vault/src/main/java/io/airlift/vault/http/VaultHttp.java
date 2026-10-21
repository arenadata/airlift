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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Throwables;
import com.google.inject.Inject;
import dev.failsafe.Failsafe;
import dev.failsafe.RetryPolicy;
import dev.failsafe.RetryPolicyBuilder;
import dev.failsafe.function.CheckedPredicate;
import dev.failsafe.function.CheckedSupplier;
import io.airlift.http.client.HeaderName;
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpUriBuilder;
import io.airlift.http.client.Request;
import io.airlift.http.client.StringResponseHandler.StringResponse;
import io.airlift.json.JsonCodec;
import io.airlift.log.Logger;
import io.airlift.vault.VaultException;
import io.airlift.vault.config.VaultConnectionConfig;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static com.google.common.net.MediaType.JSON_UTF_8;
import static io.airlift.http.client.HeaderNames.ACCEPT;
import static io.airlift.http.client.HeaderNames.CONTENT_TYPE;
import static io.airlift.http.client.HttpUriBuilder.uriBuilderFrom;
import static io.airlift.http.client.JsonBodyGenerator.jsonBodyGenerator;
import static io.airlift.http.client.Request.Builder.prepareGet;
import static io.airlift.http.client.Request.Builder.preparePost;
import static io.airlift.http.client.StringResponseHandler.createStringResponseHandler;
import static io.airlift.json.JsonCodec.mapJsonCodec;
import static java.lang.String.format;
import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.Objects.requireNonNull;

/**
 * Transport used for every exchange with the OpenBao or HashiCorp Vault HTTP API.
 * <p>
 * Both products speak the same API: the token goes in the {@code X-Vault-Token} header, the
 * namespace in {@code X-Vault-Namespace}, and an error comes back as {@code {"errors":[...]}}. Every
 * request goes through here, so a failure is classified the same way whoever made it.
 * <p>
 * Repeating a failed request belongs here too, not to the callers: a login fails for the same
 * reasons as a read of credentials, and while a server node restarts, one {@code 503} would
 * otherwise break the creation of a catalog. A request is repeated at most {@value #MAX_ATTEMPTS}
 * times, with a growing delay.
 */
public final class VaultHttp
{
    private static final Logger log = Logger.get(VaultHttp.class);

    private static final JsonCodec<Map<String, Object>> BODY_CODEC = mapJsonCodec(String.class, Object.class);

    private static final HeaderName TOKEN_HEADER = HeaderName.of("X-Vault-Token");
    private static final HeaderName NAMESPACE_HEADER = HeaderName.of("X-Vault-Namespace");

    private static final int MAX_ATTEMPTS = 3;
    private static final Duration MAX_RETRY_DURATION = Duration.ofSeconds(30);
    private static final Duration DEFAULT_RETRY_BASE_DELAY = Duration.ofMillis(100);
    private static final Duration MAX_RETRY_DELAY = Duration.ofSeconds(2);

    private final HttpClient httpClient;
    private final URI endpoint;
    private final Optional<String> namespace;
    /**
     * for a request that leaves nothing behind
     */
    private final RetryPolicy<Object> transientRetryPolicy;
    /**
     * for a request that makes the server create a secret
     */
    private final RetryPolicy<Object> unservedRequestRetryPolicy;

    @Inject
    public VaultHttp(@ForVault HttpClient httpClient, VaultConnectionConfig config)
    {
        this(httpClient, config, DEFAULT_RETRY_BASE_DELAY);
    }

    /**
     * A transport that is told how long to wait between attempts; a test sets zero. Public because
     * the tests of the user of the library build it too.
     */
    @VisibleForTesting
    public VaultHttp(HttpClient httpClient, VaultConnectionConfig config, Duration retryBaseDelay)
    {
        this.httpClient = requireNonNull(httpClient, "httpClient is null");
        requireNonNull(config, "config is null");
        this.endpoint = config.getEndpoint();
        this.namespace = config.getNamespace();
        requireNonNull(retryBaseDelay, "retryBaseDelay is null");
        this.transientRetryPolicy = retryPolicy(retryBaseDelay, VaultHttp::isTransient);
        this.unservedRequestRetryPolicy = retryPolicy(retryBaseDelay, VaultHttp::isProvablyNotServed);
    }

    /**
     * Full URI of a path below {@code /v1}, for example {@code uri("database", "creds", role)}. A
     * segment with slashes stays a path of several parts, which is what a nested mount looks like.
     */
    public URI uri(String... segments)
    {
        HttpUriBuilder builder = uriBuilderFrom(endpoint).appendPath("v1");
        for (String segment : segments) {
            builder.appendPath(segment);
        }
        return builder.build();
    }

    /**
     * A {@code GET} that leaves nothing behind on the server, repeated after any temporary failure.
     *
     * @param operation human readable prefix of every failure message, for example
     *         {@code "Failed to read credentials for role 'x' from Vault at <uri>"}
     */
    public <T> T get(URI uri, Optional<String> token, JsonCodec<T> responseCodec, String operation)
    {
        return withoutResponseContent(operation, () -> retry(transientRetryPolicy, () -> exchange(prepareGet().setUri(uri), token, responseCodec, operation)));
    }

    /**
     * A read whose errors must not include any response content or transport exception cause.
     */
    public <T> T getSecret(URI uri, Optional<String> token, JsonCodec<T> responseCodec, String operation)
    {
        return get(uri, token, responseCodec, operation);
    }

    /**
     * A {@code GET} that makes the server create a secret: reading a dynamic role gives us a new
     * database account. We repeat only what the server surely did not serve, because a lost answer
     * would leave an account nobody uses alive until its lease ends.
     */
    public <T> T getCreatingSecret(URI uri, Optional<String> token, JsonCodec<T> responseCodec, String operation)
    {
        return withoutResponseContent(operation, () -> retry(unservedRequestRetryPolicy, () -> exchange(prepareGet().setUri(uri), token, responseCodec, operation)));
    }

    /**
     * A {@code POST} we repeat after any temporary failure, because the server can do these twice
     * without harm: renewing twice moves the same lease twice.
     */
    public <T> T post(URI uri, Optional<String> token, Map<String, Object> body, JsonCodec<T> responseCodec, String operation)
    {
        return withoutResponseContent(operation, () -> retry(transientRetryPolicy, () -> exchange(postRequest(uri, body), token, responseCodec, operation)));
    }

    public <T> T postSecret(URI uri, Optional<String> token, Map<String, Object> body, JsonCodec<T> responseCodec, String operation)
    {
        return post(uri, token, body, responseCodec, operation);
    }

    /**
     * A {@code POST} that creates a secret, above all a login. It follows the narrow rule of
     * {@link #getCreatingSecret}: a repeated login leaves a token nobody holds and spends a one time
     * secret id twice, which turns a timeout into a failed login.
     */
    public <T> T postCreatingSecret(URI uri, Optional<String> token, Map<String, Object> body, JsonCodec<T> responseCodec, String operation)
    {
        return withoutResponseContent(operation, () -> retry(unservedRequestRetryPolicy, () -> exchange(postRequest(uri, body), token, responseCodec, operation)));
    }

    /**
     * A {@code POST} that answers {@code 200} or {@code 204} with an empty body, used by the
     * revocations. Never repeated: this runs while the connector shuts down, and waiting for a silent
     * server costs more than a lease that expires by itself.
     */
    public void postExpectingNoContent(URI uri, String token, Map<String, Object> body, String operation)
    {
        withoutResponseContent(operation, () -> {
            execute(postRequest(uri, body), Optional.of(token), operation);
            return null;
        });
    }

    public void postSecretExpectingNoContent(URI uri, String token, Map<String, Object> body, String operation)
    {
        postExpectingNoContent(uri, token, body, operation);
    }

    private static <T> T withoutResponseContent(String operation, Supplier<T> request)
    {
        try {
            return request.get();
        }
        catch (VaultHttpException failure) {
            // Retry classification needs the original transport cause until all attempts finish.
            // Messages created below contain only local context and status or a fixed parse error.
            // Never expose causes or suppressed exceptions from the HTTP client to callers or logs.
            throw new VaultHttpException(
                    failure.category(),
                    failure.statusCode(),
                    failure.getMessage());
        }
        catch (RuntimeException failure) {
            // Request construction and codec errors can also include supplied headers or content.
            throw new VaultHttpException(VaultException.Category.REFUSED, 0, operation + ": invalid request or response");
        }
    }

    private <T> T exchange(Request.Builder request, Optional<String> token, JsonCodec<T> responseCodec, String operation)
    {
        StringResponse response = execute(request, token, operation);
        return parse(response, responseCodec, operation);
    }

    private Request.Builder postRequest(URI uri, Map<String, Object> body)
    {
        return preparePost()
                .setUri(uri)
                .setHeader(CONTENT_TYPE, JSON_UTF_8.toString())
                .setBodyGenerator(jsonBodyGenerator(BODY_CODEC, body));
    }

    private StringResponse execute(Request.Builder request, Optional<String> token, String operation)
    {
        request.setHeader(ACCEPT, JSON_UTF_8.toString());
        token.ifPresent(value -> request.setHeader(TOKEN_HEADER, value));
        namespace.ifPresent(value -> request.setHeader(NAMESPACE_HEADER, value));

        StringResponse response;
        try {
            response = httpClient.execute(request.build(), createStringResponseHandler());
        }
        catch (RuntimeException e) {
            // the request never reached the server, or its outcome is unknown
            throw new VaultHttpException(VaultException.Category.UNAVAILABLE, 0, operation, e);
        }

        int statusCode = response.getStatusCode();
        if (statusCode < 200 || statusCode >= 300) {
            throw requestFailed(operation, response);
        }
        return response;
    }

    private <T> T parse(StringResponse response, JsonCodec<T> responseCodec, String operation)
    {
        try {
            return responseCodec.fromJson(response.getBody());
        }
        catch (IllegalArgumentException e) {
            throw new VaultHttpException(
                    VaultException.Category.REFUSED,
                    response.getStatusCode(),
                    operation + ": response is not valid JSON of the expected shape");
        }
    }

    private VaultHttpException requestFailed(String operation, StringResponse response)
    {
        int statusCode = response.getStatusCode();
        // Vault and proxy errors can echo credentials without quotes or a predictable format.
        // Do not parse or include any part of the remote error body in diagnostics.
        String message = format("%s: HTTP %s", operation, statusCode);
        if (isRetryableStatus(statusCode)) {
            return new VaultHttpException(VaultException.Category.UNAVAILABLE, statusCode, message);
        }
        return new VaultHttpException(VaultException.Category.REFUSED, statusCode, message);
    }

    /**
     * Statuses another attempt can change: 429 and 473, which the server sends while it is busy or
     * while it is a performance standby, and everything from 500 up. Anything else is a configuration
     * or a permission problem that repeating only makes worse.
     */
    private static boolean isRetryableStatus(int statusCode)
    {
        return statusCode == 429 || statusCode == 473 || statusCode >= 500;
    }

    private static <T> T retry(RetryPolicy<Object> policy, CheckedSupplier<T> request)
    {
        // Failsafe rethrows unchecked exceptions unchanged, so the caller sees the VaultException
        return Failsafe.with(policy).get(request);
    }

    /**
     * The policy handles only what the predicate accepts, and never aborts on {@link
     * io.airlift.vault.VaultException}: every retryable failure of this transport is reported as one.
     */
    private static RetryPolicy<Object> retryPolicy(Duration baseDelay, CheckedPredicate<Throwable> predicate)
    {
        RetryPolicyBuilder<Object> builder = RetryPolicy.builder()
                .withMaxAttempts(MAX_ATTEMPTS)
                // each attempt is already bounded by vault.http-client.request-timeout
                .withMaxDuration(MAX_RETRY_DURATION)
                .handleIf(predicate)
                .onFailedAttempt(attempt -> {
                    if (attempt.getLastException() instanceof VaultHttpException failure) {
                        log.debug("Vault request attempt failed: category=%s, HTTP %s", failure.category(), failure.statusCode());
                    }
                });
        // a zero base delay is what a test asks for, and Failsafe rejects both withDelay and
        // withBackoff for it: leaving the delay unset is its own way of spelling "retry immediately"
        if (!baseDelay.isZero()) {
            builder.withBackoff(baseDelay.toMillis(), MAX_RETRY_DELAY.toMillis(), MILLIS, 2).withJitter(0.2);
        }
        return builder.build();
    }

    /**
     * A failure of a request that either never reached the server, which a status of {@code 0} says,
     * or that the server itself reports as temporary.
     * <p>
     * The HTTP status distinguishes retryable replies from refusals. An application may map both
     * categories to one error code without changing this transport policy.
     */
    private static boolean isTransient(Throwable throwable)
    {
        return throwable instanceof VaultHttpException e && (e.statusCode() == 0 || isRetryableStatus(e.statusCode()));
    }

    /**
     * A request the server provably did not process, either because the connection never opened or
     * because the server answered that it did not serve it.
     */
    private static boolean isProvablyNotServed(Throwable throwable)
    {
        if (!isTransient(throwable)) {
            return false;
        }
        int statusCode = ((VaultHttpException) throwable).statusCode();
        if (statusCode != 0) {
            // 500 and 502 say the server failed while doing something, which may have been the very
            // thing that was asked of it; 503 says it did not start
            return statusCode == 429 || statusCode == 473 || statusCode == 503;
        }
        return Throwables.getCausalChain(throwable).stream()
                .anyMatch(candidate -> candidate instanceof ConnectException
                        || candidate instanceof UnknownHostException
                        || candidate instanceof NoRouteToHostException);
    }
}
