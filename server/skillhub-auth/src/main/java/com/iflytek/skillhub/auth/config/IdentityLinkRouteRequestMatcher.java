package com.iflytek.skillhub.auth.config;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Identifies the HTTP surface whose failures use the stable Identity Link
 * error contract.
 */
public final class IdentityLinkRouteRequestMatcher {

    private static final String ACCOUNT_STATE_PATH =
            "/api/v1/auth/identity-links";
    private static final String INTENT_PATH_PREFIX =
            "/api/v1/auth/identity-link-intents";

    private IdentityLinkRouteRequestMatcher() {
    }

    public static boolean matches(HttpServletRequest request) {
        String path = request.getRequestURI();
        return ACCOUNT_STATE_PATH.equals(path)
                || (path != null
                && (path.equals(INTENT_PATH_PREFIX)
                || path.startsWith(INTENT_PATH_PREFIX + "/")));
    }
}
