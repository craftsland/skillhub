package com.iflytek.skillhub.auth.identity;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.iflytek.skillhub.domain.audit.AuditLogService;
import org.junit.jupiter.api.Test;

class IdentitySecurityAuditWriterTest {

    private final AuditLogService auditLogService =
            mock(AuditLogService.class);
    private final IdentitySecurityAuditWriter writer =
            new IdentitySecurityAuditWriter(auditLogService);

    @Test
    void mapsIdentifierConflictToDedicatedAuditAction() {
        assertAuditAction(
                IdentityFailureCode.IDENTITY_IDENTIFIER_CONFLICT,
                "IDENTITY_CONFLICT_DETECTED");
    }

    @Test
    void mapsAuthorityMismatchToDedicatedAuditAction() {
        assertAuditAction(
                IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH,
                "PROVIDER_AUTHORITY_MISMATCH");
    }

    @Test
    void mapsOtherDenialsToGenericAuditAction() {
        assertAuditAction(
                IdentityFailureCode.ACCESS_DENIED,
                "IDENTITY_LOGIN_DENIED");
    }

    private void assertAuditAction(
            IdentityFailureCode failureCode,
            String expectedAction) {
        writer.recordDenied(
                "github",
                "oauth2-github",
                failureCode,
                new IdentityLoginContext(
                        "request-1",
                        "127.0.0.1",
                        "identity-test"));

        verify(auditLogService).record(
                isNull(),
                eq(expectedAction),
                eq("IDENTITY_PROVIDER"),
                isNull(),
                eq("request-1"),
                eq("127.0.0.1"),
                eq("identity-test"),
                eq("{\"providerCode\":\"github\","
                        + "\"protocol\":\"oauth2-github\","
                        + "\"reason\":\""
                        + failureCode.name()
                        + "\"}"));
    }
}
