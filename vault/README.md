# Shared Vault client

`io.airlift:vault` provides HTTP transport, authentication, database credentials
and KV reads for OpenBao and HashiCorp Vault. Its Java API lives in
`io.airlift.vault` and does not depend on Trino or JDBC. Consumers adapt the
returned credentials and exceptions to their own application contracts.
`io.airlift:secrets-vault-plugin` adapts the same client to Airlift configuration.

## Direct Java use

Create one session for an independent endpoint/authentication configuration.
Engine clients sharing that session share its token, but not a cache of KV data:

```java
VaultConnectionConfig connection = new VaultConnectionConfig()
        .setEndpoint(URI.create("https://vault.example.com:8200"))
        .setTokenFile(new File("/etc/trino/vault-token"));
HttpClientConfig transport = new HttpClientConfig()
        .setConnectTimeout(new Duration(5, SECONDS))
        .setRequestTimeout(new Duration(10, SECONDS));

try (VaultSession session = VaultSession.open(connection, transport)) {
    VaultKvClient kv = new VaultKvClient(session, new VaultKvConfig()
            .setMount("secret")
            .setVersion(2));
    String password = kv.readSecretValue("applications/service", "password");
    // Use the value without logging it. A later call reads KV again.
}
```

`VaultSession.open` creates and owns an HTTP client. Use
`VaultSession.borrowed(httpClient, connection)` when the application owns the
client, or `VaultSession.owned(httpClient, connection)` to transfer ownership.
Closing a session is idempotent, closes its owned client, and revokes only tokens
issued by its AppRole/Kubernetes login. Borrowed HTTP clients and externally
supplied tokens remain under their owner's control. Close database leases before
closing their session.

`readSecret(path)` obtains all fields with one request, so callers needing a
consistent pair can read one secret object. `readSecretValue(path, field)` requires
a top-level string field. KV v1/v2 are read-only and uncached; v2 reads the latest
version. The result's `toString()` does not print secret contents. Do not log values
extracted from it.

`VaultException` describes failures with `UNAVAILABLE` or `REFUSED` and an optional
HTTP status. Consumers translate these at their own boundary. Failures omit arbitrary
server error text and raw transport causes. Retry classification runs before
this sanitization, preserving the distinction between a connection failure and
an ambiguous timeout when issuing credentials or logging in.

## Guice use

Use a distinct binding annotation and configuration prefix for each KV client:

```java
@BindingAnnotation
@Retention(RUNTIME)
@Target({FIELD, PARAMETER, METHOD})
public @interface ForPrimarySecrets {}

@BindingAnnotation
@Retention(RUNTIME)
@Target({FIELD, PARAMETER, METHOD})
public @interface ForArchiveSecrets {}

Bootstrap bootstrap = new Bootstrap(
        new VaultKvModule("primary", ForPrimarySecrets.class),
        new VaultKvModule("archive", ForArchiveSecrets.class));
Injector injector = bootstrap.initialize();
VaultKvClient primary = injector.getInstance(Key.get(VaultKvClient.class, ForPrimarySecrets.class));
VaultKvClient archive = injector.getInstance(Key.get(VaultKvClient.class, ForArchiveSecrets.class));
```

Configure `primary.endpoint`, `primary.token-file`, `primary.kv.mount`,
`primary.kv.version`, and `primary.http-client.*`; the second client uses the
`archive.` prefix. The modules isolate sessions and tokens in private bindings,
and qualify their HTTP clients and configuration separately. Stop the owning
`LifeCycleManager` when unloading the component.
Applications embedding these modules in their existing Bootstrap use its normal
lifecycle instead of creating another one.

`VaultModule(prefix)` exposes the common session/authentication bindings for an
engine integration that supplies its own `@ForVault` HTTP client. Bind
`VaultDatabaseConfig` separately for `VaultClient`; KV clients need no database
role. For several independent clients in one injector, use private bindings as
`VaultKvModule` does.

## Configuration substitution

Applications whose properties already pass through Airlift's `SecretsResolver` can use
`${vault:path#field}` directly without adding a dependency on this library. The
`secrets-vault-plugin` plugin supplies that integration. Direct Java reads are for
consumers that need explicit runtime access, not automatic hot reload of existing
configuration beans.

The provider and direct Java API preserve literal `${...}` values. Airlift
Bootstrap also preserves properties passed through its Java setters literally.
When constructing a bootstrap from a raw programmatic configuration map, use its
explicit raw-configuration API instead. File and system properties still resolve
references once. Closing the owning Bootstrap closes its resources; stop database
credential consumers before their shared session so leases are revoked before
owned login tokens and the HTTP client.

## HTTP logging restriction

Keep `org.eclipse.jetty` at `INFO` or higher, with no child DEBUG/TRACE overrides,
in every application using this library. Jetty diagnostic logging can expose
`X-Vault-Token`, AppRole/Kubernetes login bodies and KV/database response bodies
before the library can sanitize an exception. Disabling the Airlift HTTP request
log does not disable these diagnostics.

For Trino, set `org.eclipse.jetty=INFO` in `etc/log.properties` on each node.
This restricts Jetty diagnostics throughout the JVM; the library does not change
global loggers itself. For a borrowed HTTP client, its owner is also responsible
for preventing credential/header/body logging. Safe exception messages do not
make an arbitrary logging transport safe.
