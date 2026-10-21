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
import io.airlift.vault.VaultException;
import io.airlift.vault.config.VaultConnectionConfig;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import static io.airlift.vault.VaultException.Category.REFUSED;
import static java.util.Objects.requireNonNull;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;

/**
 * Each invocation owns a new JAAS login and GSS context. Nothing is installed as a JVM-wide
 * Subject or Hadoop login, and no ticket cache, delegated credentials or password fallback is used.
 */
final class KerberosTokenGenerator
        implements Supplier<String>
{
    private final Configuration configuration;
    private final Path keytab;
    private final KerberosPrincipal principal;
    private final String servicePrincipal;
    private final LoginContextFactory loginFactory;
    private final GssContextFactory contextFactory;

    KerberosTokenGenerator(VaultConnectionConfig config)
    {
        this(config, (subject, configuration) -> new LoginContext("vault-kerberos", subject, null, configuration), KerberosTokenGenerator::createContext);
    }

    @VisibleForTesting
    KerberosTokenGenerator(VaultConnectionConfig config, LoginContextFactory loginFactory, GssContextFactory contextFactory)
    {
        requireNonNull(config, "config is null");
        this.keytab = config.getKerberosKeytab().orElseThrow().toPath();
        this.principal = new KerberosPrincipal(config.getKerberosPrincipal().orElseThrow());
        this.servicePrincipal = config.getKerberosServicePrincipal().orElseThrow();
        this.loginFactory = requireNonNull(loginFactory, "loginFactory is null");
        this.contextFactory = requireNonNull(contextFactory, "contextFactory is null");
        Map<String, String> options = Map.of(
                "principal", config.getKerberosPrincipal().orElseThrow(),
                "keyTab", config.getKerberosKeytab().orElseThrow().getAbsolutePath(),
                "useKeyTab", "true",
                "storeKey", "true",
                "isInitiator", "true",
                "doNotPrompt", "true",
                "useTicketCache", "false",
                "debug", "false");
        configuration = new Configuration()
        {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name)
            {
                return new AppConfigurationEntry[] {new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", REQUIRED, options)};
            }
        };
    }

    @Override
    public String get()
    {
        try {
            // The JDK may retain an older keytab when a replacement is invalid. Reject missing,
            // unreadable and obviously malformed files before consulting that cache. This is
            // only a header check, not a replacement for the JDK's keytab format parser.
            if (!Files.isRegularFile(keytab) || !Files.isReadable(keytab)) {
                throw new IOException("Keytab is unavailable");
            }
            try (InputStream input = Files.newInputStream(keytab)) {
                int major = input.read();
                int minor = input.read();
                if (major != 5 || (minor != 1 && minor != 2)) {
                    throw new IOException("Invalid keytab header");
                }
            }
            LoginContext login = loginFactory.create(new Subject(), configuration);
            try {
                login.login();
                // Krb5LoginModule permits a JVM property to override its configured principal.
                // A multi-principal keytab must never silently change this session's identity.
                if (!login.getSubject().getPrincipals(KerberosPrincipal.class).equals(Set.of(principal))) {
                    throw new IllegalStateException("Unexpected Kerberos login identity");
                }
                return Subject.callAs(login.getSubject(), () -> {
                    GSSContext context = contextFactory.create(servicePrincipal);
                    try {
                        context.requestMutualAuth(false);
                        context.requestCredDeleg(false);
                        byte[] token = context.initSecContext(new byte[0], 0, 0);
                        if (token == null || token.length == 0) {
                            throw new IllegalStateException("No Kerberos token generated");
                        }
                        return Base64.getEncoder().encodeToString(token);
                    }
                    finally {
                        context.dispose();
                    }
                });
            }
            finally {
                login.logout();
            }
        }
        catch (IOException | LoginException | RuntimeException failure) {
            // JAAS/JGSS exceptions and suppressed cleanup failures may expose credentials. Do not
            // retain their causes or text, even when the HTTP layer is not the caller.
            throw new VaultException(REFUSED, "Unable to authenticate to Vault with the Kerberos keytab");
        }
    }

    private static GSSContext createContext(String principal)
            throws GSSException
    {
        GSSManager manager = GSSManager.getInstance();
        Oid kerberos = new Oid("1.2.840.113554.1.2.2");
        // Explicit Kerberos principal syntax preserves the configured host and realm. OpenBao
        // accepts a raw KRB5 AP-REQ in the Negotiate header, without multi-leg negotiation.
        return manager.createContext(
                manager.createName(principal, new Oid("1.2.840.113554.1.2.2.1"), kerberos),
                kerberos,
                null,
                GSSContext.DEFAULT_LIFETIME);
    }

    @FunctionalInterface
    interface LoginContextFactory
    {
        LoginContext create(Subject subject, Configuration configuration)
                throws LoginException;
    }

    @FunctionalInterface
    interface GssContextFactory
    {
        GSSContext create(String servicePrincipal)
                throws GSSException;
    }
}
