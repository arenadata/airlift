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
import com.google.common.base.Ticker;
import com.google.common.collect.ImmutableMap;
import com.google.inject.Inject;
import io.airlift.json.JsonCodec;
import io.airlift.log.Logger;
import io.airlift.vault.VaultException;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.http.VaultHttpException;
import io.airlift.vault.model.VaultToken;
import io.airlift.vault.response.VaultLoginResponse;

import java.net.URI;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;

import static io.airlift.json.JsonCodec.jsonCodec;
import static io.airlift.json.JsonCodec.mapJsonCodec;
import static io.airlift.vault.auth.VaultLoginMethod.issuedToken;
import static java.lang.Math.max;
import static java.lang.Math.min;
import static java.lang.Math.round;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Keeps the token that a {@link VaultLoginMethod} issued: renews it, logs in again when renewing is
 * no longer possible, and revokes it when the catalog stops.
 * <p>
 * The token is refreshed after two thirds of its lifetime, with a small random shift so that the
 * nodes of a cluster do not refresh at the same moment. {@code auth/token/renew-self} comes first,
 * because it makes no new token on the server. A login happens only when the server refuses to
 * renew or stops moving the expiration. A refresh that fails while the token is still valid changes
 * nothing, we keep using that token.
 * <p>
 * There is no background thread. A token is needed for every read of credentials, and that is often
 * enough to refresh it in time. Threads that miss the cache together make one request.
 */
public final class LoginVaultTokenSupplier
        implements VaultTokenSupplier
{
    private static final Logger log = Logger.get(LoginVaultTokenSupplier.class);

    private static final JsonCodec<VaultLoginResponse> RENEWAL_CODEC = jsonCodec(VaultLoginResponse.class);
    // nothing of the lookup is used, only whether the server answers it at all
    private static final JsonCodec<Map<String, Object>> LOOKUP_CODEC = mapJsonCodec(String.class, Object.class);

    private static final long MINIMUM_LIFETIME_NANOS = SECONDS.toNanos(1);
    private static final double REFRESH_FRACTION = 2.0 / 3.0;
    private static final double REFRESH_JITTER = 0.1;
    @VisibleForTesting
    static final int MAX_SUPERSEDED_TOKENS = 8;

    private final VaultLoginMethod loginMethod;
    private final VaultHttp http;
    private final Ticker ticker;
    private final AtomicReference<CachedToken> cache = new AtomicReference<>();
    /**
     * Tokens a login replaced, waiting for {@link #shutdown()} to revoke them. Only the refreshing
     * thread adds to this queue, and the shutdown that empties it must not take the monitor of this
     * object: it would then wait for a request that is still in flight.
     */
    private final Deque<CachedToken> supersededTokens = new ConcurrentLinkedDeque<>();
    /**
     * Read on the way out of a login, written by {@link #shutdown()}, which never waits for a
     * request that is in flight.
     */
    private volatile boolean stopped;
    /**
     * Runs between publishing a new token and queueing the one it replaced. That is the short moment
     * in which a shutdown can empty the queue before the replaced token is in it. Outside a test it
     * does nothing: only a test can arrange that order instead of waiting for it.
     */
    @VisibleForTesting
    volatile Runnable beforeSupersede = () -> {};

    @Inject
    public LoginVaultTokenSupplier(VaultLoginMethod loginMethod, VaultHttp http)
    {
        this(loginMethod, http, Ticker.systemTicker());
    }

    @VisibleForTesting
    LoginVaultTokenSupplier(VaultLoginMethod loginMethod, VaultHttp http, Ticker ticker)
    {
        this.loginMethod = requireNonNull(loginMethod, "loginMethod is null");
        this.http = requireNonNull(http, "http is null");
        this.ticker = requireNonNull(ticker, "ticker is null");
    }

    @Override
    public String get()
    {
        CachedToken cached = cache.get();
        if (cached != null && !cached.needsRefresh(ticker.read())) {
            return cached.token().clientToken();
        }
        return refresh().clientToken();
    }

    /**
     * Answers a rejected request with the token to repeat it with.
     * <p>
     * If another thread has already got a new token, that is the answer, no login needed. A token
     * that is still in the cache is replaced only when the server says it does not know it. If the
     * server knows the token and still refuses, the policy is wrong, and we report that instead of
     * making another token with the same policy.
     */
    @Override
    public Optional<String> tokenAfterRejection(String rejectedToken)
    {
        requireNonNull(rejectedToken, "rejectedToken is null");
        CachedToken cached = cache.get();
        if (!isCached(cached, rejectedToken)) {
            return Optional.ofNullable(cached).map(entry -> entry.token().clientToken());
        }
        if (tokenIsStillKnown(cached.token())) {
            return Optional.empty();
        }
        // every entry carrying the rejected token is dropped, including one that a renewal in flight
        // has just re-published: renew-self hands back the very same token string
        cache.getAndUpdate(entry -> isCached(entry, rejectedToken) ? null : entry);
        return Optional.of(get());
    }

    /**
     * Revokes the token we hold and the ones a login replaced. It runs while the connector shuts
     * down, so a failure goes to the log instead of an exception: a token nobody revoked still
     * expires by itself, while an exception here would stop the steps after it.
     */
    @Override
    public void close()
    {
        shutdown();
    }

    public void shutdown()
    {
        stopped = true;
        CachedToken cached = cache.getAndSet(null);
        if (cached != null) {
            revokeSelf(cached.token());
        }
        revokeSupersededTokens();
    }

    /**
     * Revokes the tokens a login replaced. Called by {@link #shutdown()} and once more by a login
     * that finds the connector stopped: that login queues the token it replaced, and a shutdown that
     * drained the queue a moment earlier would otherwise leave it valid until the end of its
     * lifetime.
     */
    private void revokeSupersededTokens()
    {
        long nowNanos = ticker.read();
        for (CachedToken superseded = supersededTokens.pollFirst(); superseded != null; superseded = supersededTokens.pollFirst()) {
            // a token whose lifetime is over is gone from the token store, and asking the server to
            // revoke it would only cost a request while the connector is shutting down
            if (!superseded.isExpired(nowNanos)) {
                revokeSelf(superseded.token());
            }
        }
    }

    private synchronized VaultToken refresh()
    {
        throwIfStopped();
        CachedToken cached = cache.get();
        long nowNanos = ticker.read();
        if (cached != null && !cached.needsRefresh(nowNanos)) {
            return cached.token();
        }
        try {
            if (cached != null) {
                Optional<VaultToken> renewed = renew(cached);
                // publishing a renewed token is conditional: it is the same token string the cache
                // held, and losing the entry means another thread had that very token rejected
                if (renewed.isPresent() && cache.compareAndSet(cached, newEntry(renewed.orElseThrow()))) {
                    return renewed.orElseThrow();
                }
            }
            // a token that was just issued is never the one somebody rejected, so it replaces
            // whatever the cache holds
            return install(loginMethod.login());
        }
        catch (RuntimeException e) {
            // the token still works, so a server that is briefly unavailable does not fail queries.
            // A token that left the cache in the meantime was rejected and is never served again
            if (cached != null && cache.get() == cached && !cached.isExpired(ticker.read())) {
                log.warn(e, "Failed to refresh the Vault token issued by %s, the cached one is used until it expires", loginMethod.description());
                return cached.token();
            }
            throw e;
        }
    }

    /**
     * Publishes a new token, unless the connector was shut down while the login was in flight. Such
     * a token is revoked at once instead of being cached: the shutdown that would have revoked it has
     * already run, and nobody has seen it.
     */
    private VaultToken install(VaultToken token)
    {
        CachedToken entry = newEntry(token);
        CachedToken previous = cache.getAndSet(entry);
        beforeSupersede.run();
        supersede(previous);
        if (stopped) {
            cache.compareAndSet(entry, null);
            revokeSelf(token);
            // the token this login replaced was queued a moment ago, and the shutdown that drains
            // that queue may already have run
            revokeSupersededTokens();
            throw stoppedException();
        }
        return token;
    }

    /**
     * Remembers a token a login replaced, so that {@link #shutdown()} revokes it. Not here: the
     * database leases read with it belong to connections that are open right now, and revoking a
     * token revokes every lease made with it.
     */
    private void supersede(CachedToken superseded)
    {
        if (superseded == null) {
            return;
        }
        supersededTokens.addLast(superseded);
        while (supersededTokens.size() > MAX_SUPERSEDED_TOKENS) {
            log.warn(
                    "More than %s superseded Vault tokens issued by %s are waiting for revocation, the oldest one is left to expire on its own",
                    MAX_SUPERSEDED_TOKENS,
                    loginMethod.description());
            supersededTokens.pollFirst();
        }
    }

    /**
     * Does the server still know this token? That is what tells an expired or revoked token apart
     * from a policy that does not cover the path: the server answers {@code 403} to both.
     * {@code auth/token/lookup-self} is the one request every token may make, it creates nothing, and
     * the default policy grants it.
     * <p>
     * When the answer is neither yes nor a refusal, we say yes: a server we cannot reach issues no
     * tokens either, so the caller keeps the rejection it already has. A token made without the
     * default policy cannot look itself up, so we read its refusals as expiry and log in. That stays
     * bounded: a rejected request is repeated once, and the provider waits after a refused read.
     */
    private boolean tokenIsStillKnown(VaultToken token)
    {
        URI uri = http.uri("auth", "token", "lookup-self");
        String operation = format("Failed to look up the Vault token issued by %s at %s", loginMethod.description(), uri);
        try {
            http.getSecret(uri, Optional.of(token.clientToken()), LOOKUP_CODEC, operation);
            return true;
        }
        catch (VaultHttpException e) {
            if (e.statusCode() == 403) {
                log.debug(e, "Vault no longer knows the token issued by %s, logging in again", loginMethod.description());
                return false;
            }
            log.warn(
                    e,
                    "Could not check whether Vault still knows the token issued by %s, the rejection of the request is reported as it is",
                    loginMethod.description());
            return true;
        }
    }

    /**
     * Extends the lifetime of the cached token, empty when only a new token can replace it. A batch
     * token, a token whose policy does not allow renewal, a token the server no longer knows and a
     * renewal that no longer extends the lifetime because the maximum TTL of the token is in sight
     * are all normal outcomes that lead to a login rather than to a failed query.
     */
    private Optional<VaultToken> renew(CachedToken cached)
    {
        if (!cached.token().renewable()) {
            return Optional.empty();
        }
        Optional<VaultToken> renewed = renewSelf(cached.token());
        if (renewed.isEmpty() || renewed.orElseThrow().ttl().toNanos() <= cached.remainingNanos(ticker.read())) {
            return Optional.empty();
        }
        return renewed;
    }

    private Optional<VaultToken> renewSelf(VaultToken token)
    {
        URI uri = http.uri("auth", "token", "renew-self");
        String operation = format("Failed to renew the Vault token issued by %s at %s", loginMethod.description(), uri);
        try {
            VaultLoginResponse response = http.postSecret(uri, Optional.of(token.clientToken()), ImmutableMap.of(), RENEWAL_CODEC, operation);
            return Optional.of(issuedToken(response, operation));
        }
        catch (VaultHttpException e) {
            log.debug(e, "Renewing the Vault token issued by %s failed, logging in again", loginMethod.description());
            return Optional.empty();
        }
    }

    private void revokeSelf(VaultToken token)
    {
        URI uri = http.uri("auth", "token", "revoke-self");
        String operation = format("Failed to revoke the Vault token issued by %s at %s", loginMethod.description(), uri);
        try {
            http.postSecretExpectingNoContent(uri, token.clientToken(), ImmutableMap.of(), operation);
        }
        catch (RuntimeException e) {
            log.warn(e, "%s", operation);
        }
    }

    private void throwIfStopped()
    {
        if (stopped) {
            throw stoppedException();
        }
    }

    private VaultException stoppedException()
    {
        return new VaultException(
                VaultException.Category.REFUSED,
                format("The Vault token issued by %s was revoked, no token is issued while the catalog is being shut down", loginMethod.description()));
    }

    @VisibleForTesting
    int supersededTokenCount()
    {
        return supersededTokens.size();
    }

    private CachedToken newEntry(VaultToken token)
    {
        long nowNanos = ticker.read();
        long lifetimeNanos = token.ttl().toNanos();
        if (lifetimeNanos == 0) {
            // no lifetime means the token does not expire, which is the opposite of what a zero TTL
            // means for credentials, where it stands for "the server did not say"
            return new CachedToken(token, nowNanos, nowNanos, true);
        }
        double jitter = ThreadLocalRandom.current().nextDouble(-REFRESH_JITTER, REFRESH_JITTER);
        long refreshAfterNanos = min(max(round(lifetimeNanos * REFRESH_FRACTION * (1 + jitter)), MINIMUM_LIFETIME_NANOS), lifetimeNanos);
        return new CachedToken(token, nowNanos + refreshAfterNanos, nowNanos + lifetimeNanos, false);
    }

    private static boolean isCached(CachedToken cached, String token)
    {
        return cached != null && cached.token().clientToken().equals(token);
    }
}
