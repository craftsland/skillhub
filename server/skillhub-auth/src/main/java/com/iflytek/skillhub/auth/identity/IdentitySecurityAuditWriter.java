package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.domain.audit.AuditLogService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists security denials independently from the identity transaction that
 * produced them.
 */
@Service
class IdentitySecurityAuditWriter {

    private final AuditLogService auditLogService;

    IdentitySecurityAuditWriter(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordDenied(
            String providerCode,
            String protocol,
            IdentityFailureCode failureCode,
            IdentityLoginContext context) {
        String action = switch (failureCode) {
            case IDENTITY_IDENTIFIER_CONFLICT ->
                    "IDENTITY_CONFLICT_DETECTED";
            case PROVIDER_AUTHORITY_MISMATCH ->
                    "PROVIDER_AUTHORITY_MISMATCH";
            default -> "IDENTITY_LOGIN_DENIED";
        };
        auditLogService.record(
                null,
                action,
                "IDENTITY_PROVIDER",
                null,
                context.requestId(),
                context.clientIp(),
                context.userAgent(),
                "{\"providerCode\":\""
                        + providerCode
                        + "\",\"protocol\":\""
                        + protocol
                        + "\",\"reason\":\""
                        + failureCode.name()
                        + "\"}");
    }
}
