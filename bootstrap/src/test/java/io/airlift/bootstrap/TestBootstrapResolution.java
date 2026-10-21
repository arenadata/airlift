package io.airlift.bootstrap;

import io.airlift.configuration.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static io.airlift.configuration.ConfigBinder.configBinder;
import static java.nio.file.Files.writeString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.parallel.Resources.SYSTEM_PROPERTIES;

@ResourceLock(SYSTEM_PROPERTIES)
class TestBootstrapResolution
{
    @Test
    void testProgrammaticValuesAreLiteral()
    {
        String literal = "  ${ENV:FOO_PASSWORD} ${unknown:field}  ";
        try (Bootstrap bootstrap = bootstrap()
                .setRequiredConfigurationProperties(Map.of("test.value", literal))
                .setOptionalConfigurationProperty("test.other", literal)) {
            Values values = bootstrap.initialize().getInstance(Values.class);
            assertThat(values.getValue()).isEqualTo(literal);
            assertThat(values.getOther()).isEqualTo(literal);
        }
        try (Bootstrap bootstrap = bootstrap()
                .disableEnvInterpolation()
                .setRequiredConfigurationProperty("test.value", literal)
                .setOptionalConfigurationProperties(Map.of("test.other", literal))) {
            Values values = bootstrap.initialize().getInstance(Values.class);
            assertThat(values.getValue()).isEqualTo(literal);
            assertThat(values.getOther()).isEqualTo(literal);
        }
    }

    @Test
    void testRawValuesResolveOnce()
    {
        try (Bootstrap bootstrap = bootstrap()
                .setRequiredRawConfigurationProperty("test.value", "${ENV:BOOTSTRAP_LITERAL_SECRET}")
                .setOptionalRawConfigurationProperties(Map.of("test.other", "${ENV:FOO_PASSWORD}"))) {
            Values values = bootstrap.initialize().getInstance(Values.class);
            assertThat(values.getValue()).isEqualTo("literal-${ENV:FOO_PASSWORD}");
            assertThat(values.getOther()).isEqualTo("superSecretPassword");
        }
    }

    @Test
    void testOnlyWinningValuesAreResolved()
    {
        try (Bootstrap bootstrap = bootstrap()
                .setOptionalRawConfigurationProperties(Map.of("test.value", "${absent:key}"))
                .setRequiredConfigurationProperty("test.value", "${absent:literal}")) {
            assertThat(bootstrap.initialize().getInstance(Values.class).getValue()).isEqualTo("${absent:literal}");
        }
        try (Bootstrap bootstrap = bootstrap()
                .setRequiredRawConfigurationProperties(Map.of("test.value", "${absent:key}"))
                .setRequiredConfigurationProperties(Map.of("test.value", "literal"))
                .setOptionalConfigurationProperty("test.other", "${absent:literal}")
                .setOptionalRawConfigurationProperty("test.other", "${ENV:FOO_PASSWORD}")) {
            Values values = bootstrap.initialize().getInstance(Values.class);
            assertThat(values.getValue()).isEqualTo("literal");
            assertThat(values.getOther()).isEqualTo("superSecretPassword");
        }
        try (Bootstrap bootstrap = bootstrap()
                .setRequiredConfigurationProperty("test.value", "literal")
                .setRequiredRawConfigurationProperty("test.value", "${ENV:FOO_PASSWORD}")) {
            assertThat(bootstrap.initialize().getInstance(Values.class).getValue()).isEqualTo("superSecretPassword");
        }
    }

    @Test
    void testRawSystemOverrideAndDisabledOverrides()
    {
        withSystemProperty("test.value", "${ENV:BOOTSTRAP_LITERAL_SECRET}", () -> {
            try (Bootstrap bootstrap = bootstrap()
                    .withUseSystemProperties(true)
                    .setRequiredRawConfigurationProperty("test.value", "${absent:key}")) {
                assertThat(bootstrap.initialize().getInstance(Values.class).getValue()).isEqualTo("literal-${ENV:FOO_PASSWORD}");
            }
            try (Bootstrap bootstrap = bootstrap().setRequiredConfigurationProperty("test.value", "literal")) {
                assertThat(bootstrap.initialize().getInstance(Values.class).getValue()).isEqualTo("literal");
            }
        });
    }

    @Test
    void testFileValuesAreRaw(@TempDir Path directory)
            throws IOException
    {
        Path file = directory.resolve("config.properties");
        writeString(file, "test.value=${ENV:BOOTSTRAP_LITERAL_SECRET}\n");
        withSystemProperty("config", file.toString(), () -> {
            try (Bootstrap bootstrap = bootstrap()) {
                assertThat(bootstrap.initialize().getInstance(Values.class).getValue()).isEqualTo("literal-${ENV:FOO_PASSWORD}");
            }
            // Supplying even an empty required map continues to disable implicit file loading.
            try (Bootstrap bootstrap = bootstrap().setRequiredConfigurationProperties(Map.of())) {
                assertThat(bootstrap.initialize().getInstance(Values.class).getValue()).isNull();
            }
        });
    }

    @Test
    void testRawErrorsRemainStrict()
    {
        try (Bootstrap bootstrap = bootstrap().setRequiredRawConfigurationProperty("test.value", "${missing:key}")) {
            assertThatThrownBy(bootstrap::initialize)
                    .isInstanceOf(ApplicationConfigurationException.class)
                    .hasMessageContaining("No secret provider for key 'missing'")
                    .hasMessageNotContaining("was not used");
        }
        try (Bootstrap bootstrap = bootstrap().setRequiredConfigurationProperty("typo.value", "literal")) {
            assertThatThrownBy(bootstrap::initialize)
                    .isInstanceOf(ApplicationConfigurationException.class)
                    .hasMessageContaining("was not used");
        }
    }

    private static Bootstrap bootstrap()
    {
        return new Bootstrap(binder -> configBinder(binder).bindConfig(Values.class))
                .doNotInitializeLogging()
                .disableSystemProperties()
                .withShutdownHook(false)
                .quiet();
    }

    private static void withSystemProperty(String key, String value, Runnable action)
    {
        String previous = System.setProperty(key, value);
        try {
            action.run();
        }
        finally {
            if (previous == null) {
                System.clearProperty(key);
            }
            else {
                System.setProperty(key, previous);
            }
        }
    }

    public static class Values
    {
        private String value;
        private String other;

        public String getValue()
        {
            return value;
        }

        @Config("test.value")
        public Values setValue(String value)
        {
            this.value = value;
            return this;
        }

        public String getOther()
        {
            return other;
        }

        @Config("test.other")
        public Values setOther(String other)
        {
            this.other = other;
            return this;
        }
    }
}
