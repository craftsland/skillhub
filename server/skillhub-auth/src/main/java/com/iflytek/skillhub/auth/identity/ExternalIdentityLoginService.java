package com.iflytek.skillhub.auth.identity;

/**
 * The only application-facing facade for converting externally authenticated
 * provider facts into a platform login outcome.
 */
public interface ExternalIdentityLoginService {

    IdentityLoginOutcome authenticate(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context);
}
