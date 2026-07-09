package com.iflytek.skillhub.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.config.DownloadRateLimitProperties;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AnonymousDownloadIdentityServiceTest {

    @Test
    void validateAnonymousCookieSecretGeneratesRuntimeSecretForReleaseExamplePlaceholder() {
        DownloadRateLimitProperties properties = new DownloadRateLimitProperties();
        properties.setAnonymousCookieSecret("replace-with-random-download-secret-32-bytes");
        AnonymousDownloadIdentityService service = new AnonymousDownloadIdentityService(properties, new ClientIpResolver());

        service.validateAnonymousCookieSecret();

        String effectiveSecret = (String) ReflectionTestUtils.getField(service, "anonymousCookieSecret");
        assertThat(effectiveSecret)
                .isNotNull()
                .isNotEqualTo("replace-with-random-download-secret-32-bytes")
                .hasSizeGreaterThanOrEqualTo(32);
    }

    @Test
    void validateAnonymousCookieSecretRejectsLegacyPlaceholders() {
        DownloadRateLimitProperties properties = new DownloadRateLimitProperties();
        properties.setAnonymousCookieSecret("change-me-in-production");
        AnonymousDownloadIdentityService service = new AnonymousDownloadIdentityService(properties, new ClientIpResolver());

        assertThatThrownBy(service::validateAnonymousCookieSecret)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must not use the default placeholder");
    }

    @Test
    void validateAnonymousCookieSecretRejectsShortCustomSecret() {
        DownloadRateLimitProperties properties = new DownloadRateLimitProperties();
        properties.setAnonymousCookieSecret("too-short");
        AnonymousDownloadIdentityService service = new AnonymousDownloadIdentityService(properties, new ClientIpResolver());

        assertThatThrownBy(service::validateAnonymousCookieSecret)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must be at least 32 characters");
    }
}
