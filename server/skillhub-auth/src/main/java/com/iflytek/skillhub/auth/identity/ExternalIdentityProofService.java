package com.iflytek.skillhub.auth.identity;

/**
 * Resolves a verified provider exchange to an existing eligible account
 * without provisioning a new account or synchronizing profile fields.
 */
public interface ExternalIdentityProofService {

    ExternalIdentityProof authenticateExisting(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context);
}
