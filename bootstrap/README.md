# Bootstrap configuration and ownership

Programmatic configuration values are literal. The existing
`setRequiredConfigurationProperty`, `setRequiredConfigurationProperties`,
`setOptionalConfigurationProperty`, and `setOptionalConfigurationProperties`
methods do not interpret `${...}`. This includes values previously obtained from
`SecretsResolver`, copied maps, and properties reconstructed from typed config.

Applications accepting raw configuration through their Java API must instead use
`setRequiredRawConfigurationProperty` / `setRequiredRawConfigurationProperties`
or their `Optional` counterparts. This is an intentional change from the previous
implicit interpolation of programmatic properties. Direct plugin-factory callers
must resolve their raw configuration before passing it to the factory.

Configuration files and system properties remain raw. Precedence is unchanged:
optional properties, then required properties, then system properties. Resolution
runs once on the surviving raw values after merging; an overridden reference is
not fetched or validated. A literal override remains literal, while a system
property overriding it is resolved. Calling a setter again replaces both the
value and its raw/literal interpretation. `disableSystemProperties()` continues
to disable system overrides. `disableEnvInterpolation()` disables the default ENV
provider for raw values; it does not change literal values.

```java
try (Bootstrap bootstrap = new Bootstrap(modules)
        .doNotInitializeLogging()
        .disableSystemProperties()
        .withShutdownHook(false)
        .setRequiredConfigurationProperties(alreadyResolvedProperties)
        .setOptionalRawConfigurationProperty("service.password", "${ENV:PASSWORD}")) {
    Injector injector = bootstrap.initialize();
    // Use the component before its owner closes this scope.
}
```

`Bootstrap` owns its configuration factory, lifecycle-managed objects, explicitly
registered `ClosingBinder` resources, and any secrets plugin manager it creates.
`close()` is idempotent and also supports configure-only instances. Failed
configuration or injector creation automatically closes resources already owned
by the bootstrap. Consumers close before the secrets providers they depend on.

The default JVM shutdown hook is unchanged. A child runtime owned by another
component should use `withShutdownHook(false)` and have that owner call `close()`;
this avoids independent hooks with undefined relative order. A returned injector
still exposes `LifeCycleManager`, and its existing stop methods remain usable.

ClosingBinder records each resource as it is provisioned, including when another
registration fails. Explicit instances passed to `registerCloseable(instance)` or
bound with `toInstance` and registered by `Key`/`Class` are owned from configuration
onward. This includes executors and custom `registerResource` callbacks, linked
keys, and private or exposed bindings. Failed configuration or member injection
runs their registered cleanup without invoking `@PostConstruct`. Bootstrap records
modules once and reuses their Guice elements to avoid allocating those resources
again for the injector. Providers are not invoked during this ownership discovery.
Successfully injected objects with `@PreDestroy` use that lifecycle method instead
of the standard `AutoCloseable.close()` action. Custom `registerResource` cleanup
callbacks run independently, including when the resource has `@PreDestroy`.
Ordinary injected `AutoCloseable` objects
without lifecycle annotations or an explicit ClosingBinder registration remain
under the caller's ownership. Constructors that fail before returning an object
must release their own partially constructed resources.
