package com.iflytek.skillhub.auth.config;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Identifies the new safe account-merge API surface.
 */
public final class AccountMergeRouteRequestMatcher {

    private static final String PATH_PREFIX =
            "/api/v1/account/merge";

    private AccountMergeRouteRequestMatcher() {
    }

    public static boolean matches(
            HttpServletRequest request) {
        String path = request.getRequestURI();
        return path != null
                && (path.equals(PATH_PREFIX + "/capabilities")
                || path.equals(PATH_PREFIX + "/intents")
                || path.startsWith(
                        PATH_PREFIX + "/intents/")
                || path.startsWith(
                        PATH_PREFIX + "/reauthenticate/"));
    }
}
