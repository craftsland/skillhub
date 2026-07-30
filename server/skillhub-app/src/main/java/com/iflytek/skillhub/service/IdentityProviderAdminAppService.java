package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.identity.IdentityProviderAuthorityOperations;
import com.iflytek.skillhub.auth.identity.IdentityProviderAuthorityRecoveryContext;
import com.iflytek.skillhub.auth.identity.IdentityProviderAuthorityRecoveryResult;
import com.iflytek.skillhub.dto.IdentityProviderAuthorityRecoveryResponse;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

/**
 * Orchestrates authenticated identity-provider administration use cases.
 */
@Service
public class IdentityProviderAdminAppService {

    private static final String REQUEST_ID_MDC_KEY = "requestId";

    private final IdentityProviderAuthorityOperations authorityOperations;

    public IdentityProviderAdminAppService(
            IdentityProviderAuthorityOperations authorityOperations) {
        this.authorityOperations = authorityOperations;
    }

    public IdentityProviderAuthorityRecoveryResponse recoverSameAuthority(
            String providerCode,
            String actorUserId,
            AuditRequestContext auditContext) {
        IdentityProviderAuthorityRecoveryResult result =
                authorityOperations.recoverSameAuthority(
                        providerCode,
                        new IdentityProviderAuthorityRecoveryContext(
                                actorUserId,
                                bounded(
                                        MDC.get(REQUEST_ID_MDC_KEY),
                                        64),
                                bounded(auditContext.clientIp(), 64),
                                bounded(auditContext.userAgent(), 512)));
        return new IdentityProviderAuthorityRecoveryResponse(
                result.providerCode(),
                result.recovered(),
                result.state());
    }

    private String bounded(String value, int maximum) {
        return value == null || value.length() > maximum
                ? null
                : value;
    }
}
