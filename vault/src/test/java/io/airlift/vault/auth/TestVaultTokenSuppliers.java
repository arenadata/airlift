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

import io.airlift.vault.VaultException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static io.airlift.vault.VaultException.Category.REFUSED;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The two suppliers that serve a token somebody else issued: the one taken from {@code vault.token}
 * and the one read from {@code vault.token-file}. Neither talks to the server, so they are exercised
 * without an HTTP client; what the login supplier does with a token of its own is in
 * {@link TestVaultLoginTokenSupplier}.
 */
public class TestVaultTokenSuppliers
{
    private static final String CONFIGURED_TOKEN = "hvs.CAESIConfiguredToken";

    @Test
    public void testConfiguredTokenIsServedOnEveryCall()
    {
        VaultTokenSupplier tokenSupplier = new StaticVaultTokenSupplier(CONFIGURED_TOKEN);

        // the token of the configuration is what every request carries, unchanged and for as long as
        // the catalog lives
        assertThat(tokenSupplier.get()).isEqualTo(CONFIGURED_TOKEN);
        assertThat(tokenSupplier.get()).isEqualTo(CONFIGURED_TOKEN);
    }

    @Test
    public void testRejectedConfiguredTokenHasNoReplacement()
    {
        VaultTokenSupplier tokenSupplier = new StaticVaultTokenSupplier(CONFIGURED_TOKEN);

        // there is no source to obtain another token from, so a rejected request is not replayed:
        // repeating it with the same token would only cost a second rejection
        assertThat(tokenSupplier.tokenAfterRejection(CONFIGURED_TOKEN)).isEmpty();
        // not even for a token this supplier never served, which is what a file supplier would answer
        // with its current content
        assertThat(tokenSupplier.tokenAfterRejection("hvs.CAESISomeOtherToken")).isEmpty();
        assertThat(tokenSupplier.get()).isEqualTo(CONFIGURED_TOKEN);
    }

    @Test
    public void testEmptyConfiguredTokenIsRefused()
    {
        // an unset or blanked out property must not turn into an empty X-Vault-Token header on every
        // request, where the failure would be reported by the server and read as a policy problem
        assertThatThrownBy(() -> new StaticVaultTokenSupplier(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("token is null or empty");
        assertThatThrownBy(() -> new StaticVaultTokenSupplier(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("token is null or empty");
    }

    @Test
    public void testTokenFileIsStripped(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        // an operator writing the file by hand and every tool that appends a newline
        Files.writeString(tokenFile, "  hvs.CAESIFileToken \n", UTF_8);

        // whitespace around the token is not part of it: a header carrying it would be rejected
        assertThat(new FileVaultTokenSupplier(tokenFile).get()).isEqualTo("hvs.CAESIFileToken");
    }

    @Test
    public void testTokenFileIsReadOnEveryCall(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, "first-token\n", UTF_8);
        VaultTokenSupplier tokenSupplier = new FileVaultTokenSupplier(tokenFile);

        assertThat(tokenSupplier.get()).isEqualTo("first-token");
        // an agent sidecar rewrites the file in place, and the catalog is not restarted for it
        Files.writeString(tokenFile, "rotated-token\n", UTF_8);
        assertThat(tokenSupplier.get()).isEqualTo("rotated-token");
    }

    @Test
    public void testRotatedTokenFileReplacesTheRejectedToken(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, "first-token\n", UTF_8);
        VaultTokenSupplier tokenSupplier = new FileVaultTokenSupplier(tokenFile);

        assertThat(tokenSupplier.get()).isEqualTo("first-token");
        // the rotation is what made the token in flight stale, so the file already holds its successor
        Files.writeString(tokenFile, "rotated-token\n", UTF_8);
        // the replacement is handed to the caller here rather than left for the next get(): a second
        // read of the file is a second chance for it to be gone
        assertThat(tokenSupplier.tokenAfterRejection("first-token")).contains("rotated-token");
    }

    @Test
    public void testUnchangedTokenFileHasNoReplacement(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, "first-token\n", UTF_8);
        VaultTokenSupplier tokenSupplier = new FileVaultTokenSupplier(tokenFile);

        // the file still holds the token that was rejected, so replaying carries nothing new; the
        // comparison is against the stripped content, otherwise the trailing newline alone would pass
        // for a rotation and every rejection would be replayed once for nothing
        assertThat(tokenSupplier.tokenAfterRejection("first-token")).isEmpty();
    }

    @Test
    public void testMissingTokenFileIsReported(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, "first-token\n", UTF_8);
        VaultTokenSupplier tokenSupplier = new FileVaultTokenSupplier(tokenFile);

        assertThat(tokenSupplier.get()).isEqualTo("first-token");
        // the secret is unmounted, or the agent that owns the file is gone; the file existed when the
        // catalog was created, so no validation of the configuration catches this
        Files.delete(tokenFile);

        assertThatThrownBy(tokenSupplier::get)
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Failed to read Vault token file")
                .hasMessageContaining(tokenFile.toString())
                // nothing about the file changes by repeating the request, so it is a refusal and not
                // a failure worth repeating
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(REFUSED);

        // the failure to produce a replacement is reported to the caller instead of being answered
        // with "no replacement": the caller is the one holding the rejection this happened under
        assertThatThrownBy(() -> tokenSupplier.tokenAfterRejection("first-token"))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Failed to read Vault token file");
    }

    @Test
    public void testEmptyTokenFileIsReported(@TempDir Path tempDir)
            throws IOException
    {
        Path tokenFile = tempDir.resolve("token");
        // the file an agent creates before it has written the token into it
        Files.writeString(tokenFile, "", UTF_8);
        VaultTokenSupplier tokenSupplier = new FileVaultTokenSupplier(tokenFile);

        // an empty file is named as such instead of sending an empty header and letting the server
        // report a token it cannot make sense of
        assertThatThrownBy(tokenSupplier::get)
                .isInstanceOf(VaultException.class)
                .hasMessageContaining(tokenFile + " is empty")
                .extracting(throwable -> ((VaultException) throwable).category())
                .isEqualTo(REFUSED);

        // a file holding nothing but whitespace is empty too, because the content is stripped first
        Files.writeString(tokenFile, " \n\t\n", UTF_8);
        assertThatThrownBy(tokenSupplier::get)
                .isInstanceOf(VaultException.class)
                .hasMessageContaining(tokenFile + " is empty");
    }
}
