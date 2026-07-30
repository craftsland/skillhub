package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.IdentityProviderAuthorityOperations;
import com.iflytek.skillhub.auth.identity.IdentityProviderAuthorityRecoveryContext;
import com.iflytek.skillhub.auth.identity.IdentityProviderAuthorityRecoveryResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.MDC;

class IdentityProviderAdminAppServiceTest {

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void forwardsAuthenticatedOperatorAndRequestAuditMetadata() {
        IdentityProviderAuthorityOperations operations =
                mock(IdentityProviderAuthorityOperations.class);
        when(operations.recoverSameAuthority(
                eq("github"),
                org.mockito.ArgumentMatchers.any()))
                .thenReturn(new IdentityProviderAuthorityRecoveryResult(
                        "github",
                        true,
                        "READY"));
        IdentityProviderAdminAppService service =
                new IdentityProviderAdminAppService(operations);
        MDC.put("requestId", "req-123");

        var response = service.recoverSameAuthority(
                "github",
                "admin",
                new AuditRequestContext(
                        "203.0.113.9",
                        "SkillHub Browser"));

        ArgumentCaptor<IdentityProviderAuthorityRecoveryContext> context =
                ArgumentCaptor.forClass(
                        IdentityProviderAuthorityRecoveryContext.class);
        verify(operations).recoverSameAuthority(
                eq("github"),
                context.capture());
        assertThat(context.getValue()).isEqualTo(
                new IdentityProviderAuthorityRecoveryContext(
                        "admin",
                        "req-123",
                        "203.0.113.9",
                        "SkillHub Browser"));
        assertThat(response.providerCode()).isEqualTo("github");
        assertThat(response.recovered()).isTrue();
        assertThat(response.state()).isEqualTo("READY");
    }
}
