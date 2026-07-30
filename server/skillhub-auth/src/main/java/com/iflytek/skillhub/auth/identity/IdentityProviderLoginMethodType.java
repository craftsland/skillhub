package com.iflytek.skillhub.auth.identity;

/**
 * Presentation-safe interaction type for one provider login method.
 */
public enum IdentityProviderLoginMethodType {
    OAUTH_REDIRECT,
    DIRECT_PASSWORD,
    SESSION_BOOTSTRAP
}
