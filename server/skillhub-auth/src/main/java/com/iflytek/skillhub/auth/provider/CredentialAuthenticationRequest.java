package com.iflytek.skillhub.auth.provider;

/**
 * Credentials supplied to an active credential adapter.
 */
public record CredentialAuthenticationRequest(
        String username,
        String password
) {
}
