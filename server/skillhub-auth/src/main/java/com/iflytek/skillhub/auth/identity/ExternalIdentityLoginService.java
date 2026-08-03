package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;

/**
 * The only application-facing facade for converting externally authenticated
 * provider facts into a platform login outcome.
 */
public interface ExternalIdentityLoginService {

    IdentityLoginOutcome authenticate(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context);

    /**
     * Records a credential-provider denial that happened before an assertion
     * could enter the identity core.
     */
    void recordProviderAuthenticationFailure(
            ResolvedProviderHandle provider,
            ProviderAuthenticationFailureCode failureCode,
            IdentityLoginContext context);
}
