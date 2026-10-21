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

import com.google.common.collect.ImmutableList;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpClientConfig;
import io.airlift.http.client.jetty.JettyHttpClient;
import io.airlift.vault.auth.StaticVaultTokenSupplier;
import io.airlift.vault.config.VaultConnectionConfig;
import io.airlift.vault.config.VaultDatabaseConfig;
import io.airlift.vault.http.VaultHttp;
import io.airlift.vault.model.VaultCredentials;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The encrypted connection to the server, including the client certificate. Nothing of it is
 * implemented here: the {@code vault.http-client.*} properties reach Jetty, and Jetty does the work.
 * The test shows that a private certificate authority is enough for a server Java does not trust,
 * and that the client really presents its own certificate.
 * <p>
 * The certificates are made by {@code keytool} while the test runs; committed ones would expire.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TestVaultTls
{
    /**
     * The consumer of the library picks the codes, so a test of the library picks two of its own.
     */

    private static final String PASSWORD = "changeit";
    private static final String TOKEN = "trino-root-token";
    private static final String ROLE = "trino-dynamic";
    private static final String CREDENTIALS_PATH = "/v1/database/creds/" + ROLE;
    private static final String USER = "v-token-trino-dy-x9Kq3Yy2Xn8LQ0-1774000000";
    private static final String CLIENT_CERTIFICATE_NAME = "trino-client";

    private static final String CREDENTIALS_RESPONSE =
            """
            {
              "lease_id": "database/creds/trino-dynamic/tCq1V0hZ3Zc2u1jH1n1cQxWl",
              "renewable": false,
              "lease_duration": 3600,
              "data": {"username": "%s", "password": "A1a-8s0Ez7fSb7yqM2Rk"}
            }
            """.formatted(USER);

    // static, so that it exists before the server is started for the whole class
    @TempDir
    private static Path certificates;

    private Path serverKeyStore;
    private Path serverTrustStore;
    private Path clientKeyStore;
    private Path clientTrustStore;
    private HttpsServer server;
    private URI endpoint;
    private final List<String> clientCertificateNames = new CopyOnWriteArrayList<>();

    @BeforeAll
    void startServer()
            throws Exception
    {
        serverKeyStore = certificates.resolve("server.p12");
        serverTrustStore = certificates.resolve("server-truststore.p12");
        clientKeyStore = certificates.resolve("client.p12");
        clientTrustStore = certificates.resolve("client-truststore.p12");

        Path serverCertificate = certificates.resolve("server.crt");
        Path clientCertificate = certificates.resolve("client.crt");
        // the server certificate is issued for the name the client connects to, so that the host name
        // is verified rather than skipped
        generateKeyPair(serverKeyStore, "localhost");
        exportCertificate(serverKeyStore, serverCertificate);
        generateKeyPair(clientKeyStore, CLIENT_CERTIFICATE_NAME);
        exportCertificate(clientKeyStore, clientCertificate);
        // each side trusts exactly one certificate, and neither is signed by an authority Java ships
        importCertificate(clientTrustStore, serverCertificate);
        importCertificate(serverTrustStore, clientCertificate);

        SSLContext sslContext = sslContext(serverKeyStore, serverTrustStore);
        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext)
        {
            @Override
            public void configure(HttpsParameters parameters)
            {
                SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
                // a client without a certificate is refused, which is what makes the successful read
                // below evidence of mutual TLS
                sslParameters.setNeedClientAuth(true);
                parameters.setSSLParameters(sslParameters);
            }
        });
        server.createContext(CREDENTIALS_PATH, exchange -> {
            clientCertificateNames.add(((HttpsExchange) exchange).getSSLSession().getPeerPrincipal().getName());
            byte[] body = CREDENTIALS_RESPONSE.getBytes(UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();
        endpoint = URI.create("https://localhost:" + server.getAddress().getPort());
    }

    @AfterAll
    void stopServer()
    {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void testCredentialsAreReadOverMutualTls()
            throws Exception
    {
        HttpClientConfig clientConfig = new HttpClientConfig()
                .setTrustStorePath(clientTrustStore.toString())
                .setTrustStorePassword(PASSWORD)
                .setKeyStorePath(clientKeyStore.toString())
                .setKeyStorePassword(PASSWORD);

        VaultCredentials credentials = readCredentials(clientConfig);

        assertThat(credentials.username()).isEqualTo(USER);
        // the server saw the certificate of this client, so the properties configured a key store and
        // did not merely allow the connection
        assertThat(clientCertificateNames).containsExactly("CN=" + CLIENT_CERTIFICATE_NAME);
    }

    @Test
    void testServerCertificateSignedByAnUnknownAuthorityIsRefused()
    {
        // no vault.http-client.trust-store-path: the certificate of the server is not one Java trusts
        HttpClientConfig clientConfig = new HttpClientConfig()
                .setKeyStorePath(clientKeyStore.toString())
                .setKeyStorePassword(PASSWORD);

        assertThatThrownBy(() -> readCredentials(clientConfig))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Failed to read credentials for role '%s'".formatted(ROLE));
    }

    @Test
    void testClientWithoutACertificateIsRefused()
    {
        // the server is trusted, but nothing is presented to it in return
        HttpClientConfig clientConfig = new HttpClientConfig()
                .setTrustStorePath(clientTrustStore.toString())
                .setTrustStorePassword(PASSWORD);

        assertThatThrownBy(() -> readCredentials(clientConfig))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Failed to read credentials for role '%s'".formatted(ROLE));
    }

    private VaultCredentials readCredentials(HttpClientConfig clientConfig)
    {
        VaultConnectionConfig config = new VaultConnectionConfig()
                .setEndpoint(endpoint)
                .setToken(TOKEN);
        try (HttpClient httpClient = new JettyHttpClient("vault-tls", clientConfig)) {
            // retries must not sleep in a unit test
            VaultHttp http = new VaultHttp(httpClient, config, Duration.ZERO);
            return new VaultClient(new VaultSession(http, new StaticVaultTokenSupplier(TOKEN)), new VaultDatabaseConfig().setRole(ROLE)).readCredentials();
        }
    }

    private static void generateKeyPair(Path keyStore, String commonName)
    {
        keytool("-genkeypair",
                "-alias",
                "trino",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "1",
                "-dname",
                "CN=" + commonName,
                "-ext",
                "SAN=dns:localhost,ip:127.0.0.1",
                "-keystore",
                keyStore.toString(),
                "-storepass",
                PASSWORD,
                "-keypass",
                PASSWORD);
    }

    private static void exportCertificate(Path keyStore, Path certificate)
    {
        keytool("-exportcert",
                "-alias",
                "trino",
                "-rfc",
                "-keystore",
                keyStore.toString(),
                "-storepass",
                PASSWORD,
                "-file",
                certificate.toString());
    }

    private static void importCertificate(Path trustStore, Path certificate)
    {
        keytool("-importcert",
                "-noprompt",
                "-alias",
                "trusted",
                "-file",
                certificate.toString(),
                "-keystore",
                trustStore.toString(),
                "-storepass",
                PASSWORD);
    }

    private static void keytool(String... arguments)
    {
        List<String> command = ImmutableList.<String>builder()
                .add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString())
                .add(arguments)
                .build();
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            String output;
            try (InputStream input = process.getInputStream()) {
                output = new String(input.readAllBytes(), UTF_8);
            }
            int status = process.waitFor();
            assertThat(status)
                    .describedAs("keytool %s failed: %s", command, output)
                    .isEqualTo(0);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    private static SSLContext sslContext(Path keyStorePath, Path trustStorePath)
            throws Exception
    {
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(loadKeyStore(keyStorePath), PASSWORD.toCharArray());
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(loadKeyStore(trustStorePath));
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
        return sslContext;
    }

    private static KeyStore loadKeyStore(Path path)
            throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(path)) {
            keyStore.load(input, PASSWORD.toCharArray());
        }
        return keyStore;
    }
}
