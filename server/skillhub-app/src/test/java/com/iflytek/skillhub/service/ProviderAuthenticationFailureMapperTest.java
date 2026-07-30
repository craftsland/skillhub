package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

class ProviderAuthenticationFailureMapperTest {

    @Test
    void mapsStableProviderFailuresWithoutExposingUpstreamDetails() {
        assertMapping(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_CREDENTIALS,
                HttpStatus.UNAUTHORIZED);
        assertMapping(
                ProviderAuthenticationFailureCode.REPLAY_DETECTED,
                HttpStatus.UNAUTHORIZED);
        assertMapping(
                ProviderAuthenticationFailureCode.UPSTREAM_ACCESS_DENIED,
                HttpStatus.FORBIDDEN);
        assertMapping(
                ProviderAuthenticationFailureCode.UPSTREAM_UNAVAILABLE,
                HttpStatus.SERVICE_UNAVAILABLE);
        assertMapping(
                ProviderAuthenticationFailureCode.UPSTREAM_MISCONFIGURED,
                HttpStatus.SERVICE_UNAVAILABLE);
        assertMapping(
                ProviderAuthenticationFailureCode.TLS_VALIDATION_FAILED,
                HttpStatus.SERVICE_UNAVAILABLE);
        assertMapping(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE,
                HttpStatus.SERVICE_UNAVAILABLE);
    }

    private void assertMapping(
            ProviderAuthenticationFailureCode reasonCode,
            HttpStatus status) {
        AuthFlowException mapped =
                ProviderAuthenticationFailureMapper.map(
                        new ProviderAuthenticationException(
                                reasonCode,
                                new IllegalStateException(
                                        "private upstream detail")));

        assertThat(mapped.getStatus()).isEqualTo(status);
        assertThat(mapped.getMessage())
                .doesNotContain("private upstream detail");
    }
}
