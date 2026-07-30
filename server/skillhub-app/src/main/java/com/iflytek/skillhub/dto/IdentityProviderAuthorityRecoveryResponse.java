package com.iflytek.skillhub.dto;

/**
 * Result of an administrative same-authority recovery operation.
 */
public record IdentityProviderAuthorityRecoveryResponse(
        String providerCode,
        boolean recovered,
        String state
) {
}
