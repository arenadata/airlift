# Vault configuration secrets

`io.airlift:secrets-vault-plugin` supplies the `vault` secrets provider for
Airlift applications. It uses `io.airlift:vault` for transport, authentication,
and KV reads. It has no dependency on Trino or JDBC; `secrets-spi` is provided
by the application. The ZIP includes its other runtime dependencies.

Unpack the ZIP into its own directory under the configured secrets plugin
folder. Each TOML namespace creates an independent client, token state and
lifecycle:

```toml
[vault]
secrets-provider.name = "vault"
vault.endpoint = "https://vault.example.com:8200"
vault.auth.method = "TOKEN"
vault.token-file = "/etc/application/vault-token"
vault.kv.mount = "secret"
vault.kv.version = "2"

[archive]
secrets-provider.name = "vault"
vault.endpoint = "https://archive-vault.example.com:8200"
vault.auth.method = "TOKEN"
vault.token-file = "/etc/application/archive-token"
vault.kv.mount = "legacy"
vault.kv.version = "1"
```

The reference is `path#field`, where the path is relative to the namespace's
mount and the field is a top-level string field:

```properties
internal-communication.shared-secret=${vault:trino/server#shared-secret}
connection-password=${archive:databases/orders#password}
```

Mount `secret` and KV version `2` are defaults. Version `1` is also supported;
the version is never autodetected. KV v2 reads the latest version. Missing or
deleted secrets, missing or non-string fields, malformed responses, and Vault
failures cause configuration loading to fail with a sanitized error. Values are
returned verbatim, including whitespace and literal `${...}`. KV values are not
cached. Configuration substitution happens when a component is created; it does
not update an already-created component after Vault changes.

`TOKEN`, `APPROLE`, `KUBERNETES`, and `KERBEROS` authentication share the
[client's connection configuration](../vault/README.md). HTTP TLS, mTLS,
timeouts, and connection settings use the `vault.http-client.` prefix. TOML
provider properties are expanded for ENV references by `SecretsPluginManager`
once, before the factory receives them; the provider Bootstrap does not expand
them again or take system-property overrides.

For keytab authentication, use the `vault.auth.kerberos.*` properties documented
in the shared client. The keytab and CA must be available to the process before
the parent application Bootstrap resolves its HTTPS and internal communication
secrets. This mode performs an isolated JAAS login; it does not reuse a connector's
Hadoop Subject or a ticket cache. It implements OpenBao's single-leg client
authentication over verified HTTPS, without claiming Kerberos mutual authentication.

The secrets manager owns each provider. Closing the manager closes each provider
under its plugin classloader, revokes tokens created by its login, and closes its
HTTP client. Supplied tokens are not revoked. A provider created directly through
the Java factory must be closed by its caller. Nested provider bootstraps do not
install JVM shutdown hooks; the application's owning Bootstrap manages shutdown.

Provider failures never include Vault response bodies, raw transport causes, or
secret values. The consuming configuration property must use
`@ConfigSecuritySensitive` to mask its resolved value in configuration diagnostics.
After substitution the value is present in the consumer's memory. Keep
`org.eclipse.jetty` at `INFO` or higher with no DEBUG/TRACE child overrides: Jetty
wire diagnostics can expose headers and bodies before application sanitization.

The integration test runs after packaging and loads the ZIP with the actual
isolated `SecretsPluginManager`. It covers two independent namespaces, KV v1/v2
against OpenBao 2.6.1, literal values, rotation without a KV cache, token-file
recovery after 403, deleted versions, and caller ownership of supplied tokens.
