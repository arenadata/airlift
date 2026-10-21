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

import io.airlift.http.client.testing.TestingHttpClient;
import io.airlift.vault.auth.VaultTokenSupplier;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.http.VaultHttpException;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static io.airlift.vault.VaultException.Category.REFUSED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TestVaultSession
{
    @Test
    void testNullResultAfterTokenReplacementAndIdempotentClose()
    {
        AtomicInteger closes = new AtomicInteger();
        AtomicInteger requests = new AtomicInteger();
        VaultTokenSupplier supplier = new VaultTokenSupplier()
        {
            @Override
            public String get()
            {
                return "old";
            }

            @Override
            public Optional<String> tokenAfterRejection(String rejectedToken)
            {
                assertThat(rejectedToken).isEqualTo("old");
                return Optional.of("new");
            }

            @Override
            public void close()
            {
                closes.incrementAndGet();
            }
        };
        TestingHttpClient http = new TestingHttpClient(_ -> { throw new AssertionError("No HTTP expected"); });
        VaultSession session = new VaultSession(new VaultHttp(http, config()), supplier);
        assertThat(session.<Void>withToken(token -> {
            requests.incrementAndGet();
            if (token.equals("old")) {
                throw new VaultHttpException(REFUSED, 403, "token rejected");
            }
            return null;
        })).isNull();
        assertThat(requests).hasValue(2);
        requests.set(0);
        assertThatThrownBy(() -> session.withToken(_ -> {
            requests.incrementAndGet();
            throw new VaultHttpException(REFUSED, 403, "policy refused");
        })).hasMessage("policy refused");
        assertThat(requests).hasValue(2);
        session.close();
        session.close();
        assertThat(closes).hasValue(1);
        assertThat(http.isClosed()).isFalse();
        assertThatThrownBy(() -> session.withToken(_ -> "unused")).isInstanceOf(VaultException.class);
        http.close();
    }

    @Test
    void testHttpOwnershipAndConstructionFailure()
    {
        TestingHttpClient borrowedHttp = new TestingHttpClient(_ -> { throw new AssertionError("No HTTP expected"); });
        VaultSession.borrowed(borrowedHttp, config()).close();
        assertThat(borrowedHttp.isClosed()).isFalse();
        borrowedHttp.close();

        TestingHttpClient ownedHttp = new TestingHttpClient(_ -> { throw new AssertionError("No HTTP expected"); });
        VaultSession.owned(ownedHttp, config()).close();
        assertThat(ownedHttp.isClosed()).isTrue();

        TestingHttpClient failingHttp = new TestingHttpClient(_ -> { throw new AssertionError("No HTTP expected"); });
        assertThatThrownBy(() -> VaultSession.owned(failingHttp, config().setToken(null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(failingHttp.isClosed()).isTrue();
    }

    private static VaultConnectionConfig config()
    {
        return new VaultConnectionConfig().setEndpoint(URI.create("http://vault.invalid:8200")).setToken("test-token");
    }
}
