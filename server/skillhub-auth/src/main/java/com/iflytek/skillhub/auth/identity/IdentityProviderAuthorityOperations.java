package com.iflytek.skillhub.auth.identity;

/**
 * Administrative operations for a persisted provider authority lock.
 */
public interface IdentityProviderAuthorityOperations {

    IdentityProviderAuthorityRecoveryResult recoverSameAuthority(
            String providerCode,
            IdentityProviderAuthorityRecoveryContext context);
}
