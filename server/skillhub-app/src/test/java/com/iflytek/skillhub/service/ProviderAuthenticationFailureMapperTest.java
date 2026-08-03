package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityLinkException;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.merge.AccountMergeException;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
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
                ProviderAuthenticationFailureCode
                        .UPSTREAM_IDENTITY_NOT_FOUND,
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

    @Test
    void mapsStableProviderFailuresToIdentityLinkReasonCodes() {
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_CREDENTIALS,
                IdentityLinkFailureCode.PROVIDER_AUTHENTICATION_FAILED);
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_IDENTITY_NOT_FOUND,
                IdentityLinkFailureCode.PROVIDER_AUTHENTICATION_FAILED);
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode.UPSTREAM_ACCESS_DENIED,
                IdentityLinkFailureCode.PROVIDER_AUTHENTICATION_FAILED);
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode.REPLAY_DETECTED,
                IdentityLinkFailureCode.PROVIDER_AUTHENTICATION_FAILED);
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode.UPSTREAM_UNAVAILABLE,
                IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode.UPSTREAM_MISCONFIGURED,
                IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode.TLS_VALIDATION_FAILED,
                IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        assertIdentityLinkMapping(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE,
                IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
    }

    @Test
    void mapsStableProviderFailuresToAccountMergeReasonCodes() {
        assertAccountMergeMapping(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_CREDENTIALS,
                AccountMergeFailureCode
                        .MERGE_PROVIDER_AUTHENTICATION_FAILED);
        assertAccountMergeMapping(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_IDENTITY_NOT_FOUND,
                AccountMergeFailureCode
                        .MERGE_PROVIDER_AUTHENTICATION_FAILED);
        assertAccountMergeMapping(
                ProviderAuthenticationFailureCode.UPSTREAM_UNAVAILABLE,
                AccountMergeFailureCode.MERGE_PROVIDER_UNAVAILABLE);
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

    private void assertIdentityLinkMapping(
            ProviderAuthenticationFailureCode providerReasonCode,
            IdentityLinkFailureCode identityLinkReasonCode) {
        IdentityLinkException mapped =
                ProviderAuthenticationFailureMapper.mapIdentityLink(
                        new ProviderAuthenticationException(
                                providerReasonCode,
                                new IllegalStateException(
                                        "private upstream detail")));

        assertThat(mapped.getStatus())
                .isEqualTo(identityLinkReasonCode.status());
        assertThat(mapped.getReasonCode())
                .isEqualTo(identityLinkReasonCode);
        assertThat(mapped.getMessage())
                .doesNotContain("private upstream detail");
    }

    private void assertAccountMergeMapping(
            ProviderAuthenticationFailureCode providerReasonCode,
            AccountMergeFailureCode accountMergeReasonCode) {
        AccountMergeException mapped =
                ProviderAuthenticationFailureMapper.mapAccountMerge(
                        new ProviderAuthenticationException(
                                providerReasonCode,
                                new IllegalStateException(
                                        "private upstream detail")));

        assertThat(mapped.getStatus())
                .isEqualTo(accountMergeReasonCode.status());
        assertThat(mapped.getReasonCode())
                .isEqualTo(accountMergeReasonCode);
        assertThat(mapped.getMessage())
                .doesNotContain("private upstream detail");
    }
}
