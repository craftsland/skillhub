package com.iflytek.skillhub.auth.direct;

/**
 * @deprecated use
 * {@link com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest}.
 */
@Deprecated(forRemoval = true)
public record DirectAuthRequest(
    String username,
    String password
) {}
