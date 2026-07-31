package com.iflytek.skillhub.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SensitiveLogSanitizerTest {

    private final SensitiveLogSanitizer sanitizer = new SensitiveLogSanitizer();

    @Test
    void shouldRedactSensitiveQueryParameters() {
        String sanitized = sanitizer.sanitizeQuery(
                "returnTo=%2Fdashboard&token=abc123&password=secret"
                        + "&code=xyz&ticket=ST-secret&state=state-secret");

        assertThat(sanitized).contains("returnTo=%2Fdashboard");
        assertThat(sanitized).contains("token=[REDACTED]");
        assertThat(sanitized).contains("password=[REDACTED]");
        assertThat(sanitized).contains("code=[REDACTED]");
        assertThat(sanitized).contains("ticket=[REDACTED]");
        assertThat(sanitized).contains("state=[REDACTED]");
        assertThat(sanitized)
                .doesNotContain("ST-secret")
                .doesNotContain("state-secret");
    }

    @Test
    void shouldRedactEncodedAndMalformedSensitiveKeys() {
        String sanitized = sanitizer.sanitizeQuery(
                "ti%63ket=ST-encoded-secret"
                        + "&st%61te=encoded-state-secret"
                        + "&bad%=unknown-secret");

        assertThat(sanitized)
                .contains("ti%63ket=[REDACTED]")
                .contains("st%61te=[REDACTED]")
                .contains("bad%=[REDACTED]")
                .doesNotContain("ST-encoded-secret")
                .doesNotContain("encoded-state-secret")
                .doesNotContain("unknown-secret");
    }
}
