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
import io.airlift.json.JsonCodec;
import io.airlift.vault.config.VaultKvConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.http.VaultHttpException;
import io.airlift.vault.model.VaultSecret;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static io.airlift.json.JsonCodec.mapJsonCodec;
import static io.airlift.vault.VaultSecretException.Reason.DELETED_OR_DESTROYED;
import static io.airlift.vault.VaultSecretException.Reason.INVALID_RESPONSE;
import static io.airlift.vault.VaultSecretException.Reason.MISSING_OR_NON_STRING_FIELD;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

/**
 * Reads the current KV value on every call; configuration interpolation owns any caching policy.
 */
public final class VaultKvClient
{
    private static final JsonCodec<Map<String, Object>> RESPONSE_CODEC = mapJsonCodec(String.class, Object.class);

    private final VaultSession session;
    private final String mount;
    private final int version;

    @Inject
    public VaultKvClient(VaultSession session, VaultKvConfig config)
    {
        this.session = requireNonNull(session, "session is null");
        requireNonNull(config, "config is null");
        this.mount = requirePath(config.getMount(), "KV mount");
        this.version = config.getVersion();
        checkArgument(version == 1 || version == 2, "KV version must be 1 or 2");
    }

    public VaultSecret readSecret(String path)
    {
        requirePath(path, "KV secret path");
        VaultHttp http = session.http();
        URI uri = version == 1 ? http.uri(mount, path) : http.uri(mount, "data", path);
        String operation = format("Failed to read Vault KV secret at %s", uri);
        Map<String, Object> response;
        try {
            response = session.withToken(token -> http.getSecret(uri, Optional.of(token), RESPONSE_CODEC, operation));
        }
        catch (VaultHttpException failure) {
            if (failure.statusCode() >= 200 && failure.statusCode() < 300) {
                throw new VaultSecretException(INVALID_RESPONSE);
            }
            throw failure;
        }
        Map<String, Object> data = object(response == null ? null : response.get("data"));
        if (version == 2) {
            Object metadataValue = data.get("metadata");
            if (metadataValue instanceof Map<?, ?> metadata &&
                    (Boolean.TRUE.equals(metadata.get("destroyed")) ||
                            metadata.get("deletion_time") instanceof String deleted && !deleted.isEmpty())) {
                throw new VaultSecretException(DELETED_OR_DESTROYED);
            }
            data = object(data.get("data"));
        }
        return new VaultSecret(data);
    }

    public String readSecretValue(String path, String key)
    {
        checkArgument(key != null && !key.isEmpty(), "KV secret key is empty");
        Object value = readSecret(path).values().get(key);
        if (!(value instanceof String string)) {
            throw new VaultSecretException(MISSING_OR_NON_STRING_FIELD);
        }
        return string;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value)
    {
        if (!(value instanceof Map<?, ?> map)) {
            throw new VaultSecretException(INVALID_RESPONSE);
        }
        return (Map<String, Object>) map;
    }

    private static String requirePath(String path, String description)
    {
        checkArgument(path != null && !path.isBlank(), "%s is empty", description);
        for (String segment : path.split("/", -1)) {
            checkArgument(!segment.isEmpty() && !segment.equals(".") && !segment.equals(".."), "%s must be a relative path without empty or dot segments", description);
        }
        return path;
    }
}
