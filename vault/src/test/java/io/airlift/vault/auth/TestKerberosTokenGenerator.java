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
import io.airlift.vault.config.VaultConnectionConfig;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TestKerberosTokenGenerator
{
    @TempDir
    Path directory;

    private Path keytab;

    @BeforeEach
    void setup()
            throws Exception
    {
        keytab = Files.write(directory.resolve("client.keytab"), new byte[] {5, 2});
    }

    @Test
    void testIsolatedSubjectFreshLoginOptionsAndCleanup()
    {
        List<Subject> subjects = new ArrayList<>();
        AtomicInteger logouts = new AtomicInteger();
        AtomicInteger disposals = new AtomicInteger();
        List<Boolean> mutual = new ArrayList<>();
        List<Boolean> delegation = new ArrayList<>();
        Subject outer = Subject.current();
        KerberosTokenGenerator generator = new KerberosTokenGenerator(config(), (subject, configuration) -> {
            subjects.add(subject);
            Map<String, ?> options = configuration.getAppConfigurationEntry("vault")[0].getOptions();
            assertThat(options.get("useTicketCache")).isEqualTo("false");
            assertThat(options.get("doNotPrompt")).isEqualTo("true");
            assertThat(options.get("isInitiator")).isEqualTo("true");
            assertThat(options.get("useKeyTab")).isEqualTo("true");
            assertThat(options.get("debug")).isEqualTo("false");
            assertThat(options.get("principal")).isEqualTo("trino/node@REALM");
            assertThat(options.get("keyTab")).isEqualTo(keytab.toString());
            return login(subject, configuration, logouts, false, false);
        }, service -> {
            assertThat(service).isEqualTo("HTTP/bao@REALM");
            assertThat(Subject.current()).isSameAs(subjects.getLast()).isNotSameAs(outer);
            return (GSSContext) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {GSSContext.class}, (_, method, arguments) -> switch (method.getName()) {
                case "requestMutualAuth" -> {
                    mutual.add((boolean) arguments[0]);
                    yield null;
                }
                case "requestCredDeleg" -> {
                    delegation.add((boolean) arguments[0]);
                    yield null;
                }
                case "initSecContext" -> new byte[] {(byte) subjects.size()};
                case "dispose" -> {
                    disposals.incrementAndGet();
                    yield null;
                }
                default -> throw new AssertionError(method.getName());
            });
        });
        assertThat(generator.get()).isEqualTo("AQ==");
        assertThat(generator.get()).isEqualTo("Ag==");
        assertThat(subjects).hasSize(2);
        assertThat(subjects.getFirst()).isNotSameAs(subjects.getLast());
        assertThat(mutual).containsExactly(false, false);
        assertThat(delegation).containsExactly(false, false);
        assertThat(logouts.get()).isEqualTo(2);
        assertThat(disposals.get()).isEqualTo(2);
        assertThat(Subject.current()).isSameAs(outer);
    }

    @Test
    void testKeytabPreflightOnEveryLogin()
            throws Exception
    {
        KerberosTokenGenerator generator = new KerberosTokenGenerator(config(),
                (_, _) -> { throw new AssertionError("Invalid keytab must not reach JAAS"); },
                _ -> { throw new AssertionError("Invalid keytab must not reach GSS"); });
        for (byte[] invalid : List.of(new byte[0], new byte[] {5}, new byte[] {0, 1, 2, 3}, new byte[] {5, 3})) {
            Files.write(keytab, invalid);
            assertThatThrownBy(generator::get).isInstanceOf(VaultException.class).hasNoCause()
                    .hasMessage("Unable to authenticate to Vault with the Kerberos keytab");
        }
        Files.delete(keytab);
        assertThatThrownBy(generator::get).isInstanceOf(VaultException.class).hasNoCause();
        Files.createDirectory(keytab);
        assertThatThrownBy(generator::get).isInstanceOf(VaultException.class).hasNoCause();
    }

    @Test
    void testFailureCleanupAndSanitization()
    {
        for (String phase : List.of("login", "create", "token", "dispose", "logout")) {
            AtomicInteger logouts = new AtomicInteger();
            AtomicInteger disposals = new AtomicInteger();
            Subject outer = Subject.current();
            KerberosTokenGenerator generator = new KerberosTokenGenerator(config(),
                    (subject, configuration) -> login(subject, configuration, logouts, phase.equals("login"), phase.equals("logout")),
                    _ -> {
                        if (phase.equals("create")) {
                            throw new GSSException(GSSException.FAILURE, 0, "private-create");
                        }
                        return (GSSContext) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {GSSContext.class}, (_, method, _) -> {
                            if (method.getName().equals("dispose")) {
                                disposals.incrementAndGet();
                                if (phase.equals("dispose")) {
                                    throw new GSSException(GSSException.FAILURE, 0, "private-dispose");
                                }
                            }
                            if (method.getName().equals("initSecContext")) {
                                if (phase.equals("token")) {
                                    throw new GSSException(GSSException.FAILURE, 0, "private-token");
                                }
                                return new byte[] {1};
                            }
                            return null;
                        });
                    });
            assertThatThrownBy(generator::get).as(phase).isInstanceOf(VaultException.class)
                    .hasNoCause().hasMessageNotContaining("private").satisfies(error -> assertThat(error.getSuppressed()).isEmpty());
            assertThat(logouts.get()).as(phase).isEqualTo(1);
            assertThat(disposals.get()).as(phase).isEqualTo(phase.equals("login") || phase.equals("create") ? 0 : 1);
            assertThat(Subject.current()).isSameAs(outer);
        }
    }

    @Test
    void testUnexpectedSubjectIdentityCannotCreateGssContext()
    {
        for (boolean includeExpected : List.of(false, true)) {
            AtomicInteger logouts = new AtomicInteger();
            KerberosTokenGenerator generator = new KerberosTokenGenerator(config(), (subject, configuration) -> {
                // Models sun.security.krb5.principal overriding the JAAS option, including a
                // keytab which also holds the HTTP principal. Never mutate that global property.
                subject.getPrincipals().add(new KerberosPrincipal("HTTP/node@REALM"));
                if (includeExpected) {
                    subject.getPrincipals().add(new KerberosPrincipal("trino/node@REALM"));
                }
                return new LoginContext("test", subject, null, configuration)
                {
                    @Override
                    public void login() {}

                    @Override
                    public void logout()
                    {
                        logouts.incrementAndGet();
                    }
                };
            }, _ -> { throw new AssertionError("Wrong Subject must not reach GSS"); });
            assertThatThrownBy(generator::get).isInstanceOf(VaultException.class).hasNoCause();
            assertThat(logouts.get()).isEqualTo(1);
        }
    }

    private static LoginContext login(Subject subject, Configuration configuration, AtomicInteger logouts, boolean failLogin, boolean failLogout)
            throws LoginException
    {
        return new LoginContext("test", subject, null, configuration)
        {
            @Override
            public void login()
                    throws LoginException
            {
                if (failLogin) {
                    throw new LoginException("private-login");
                }
                subject.getPrincipals().add(new KerberosPrincipal("trino/node@REALM"));
            }

            @Override
            public void logout()
                    throws LoginException
            {
                logouts.incrementAndGet();
                if (failLogout) {
                    throw new LoginException("private-logout");
                }
            }
        };
    }

    private VaultConnectionConfig config()
    {
        return new VaultConnectionConfig().setKerberosPrincipal("trino/node@REALM")
                .setKerberosServicePrincipal("HTTP/bao@REALM").setKerberosKeytab(keytab.toFile());
    }
}
