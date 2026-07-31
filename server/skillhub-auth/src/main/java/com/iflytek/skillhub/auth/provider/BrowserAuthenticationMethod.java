package com.iflytek.skillhub.auth.provider;

/**
 * Core-recognized browser interaction used to project a fixed first-party
 * login route. Adapters do not provide arbitrary action URLs.
 */
public enum BrowserAuthenticationMethod {
    OAUTH_REDIRECT,
    CAS_REDIRECT
}
