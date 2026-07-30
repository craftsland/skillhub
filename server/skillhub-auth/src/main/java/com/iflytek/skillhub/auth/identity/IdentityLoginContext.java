package com.iflytek.skillhub.auth.identity;

/**
 * Non-sensitive request metadata available to the identity core for audit and
 * metrics. It deliberately does not expose servlet or session objects.
 */
public record IdentityLoginContext(
        String requestId,
        String clientIp,
        String userAgent
) {
    public IdentityLoginContext {
        validateLength(requestId, 64, "requestId");
        validateLength(clientIp, 64, "clientIp");
        validateLength(userAgent, 512, "userAgent");
    }

    public static IdentityLoginContext empty() {
        return new IdentityLoginContext(null, null, null);
    }

    private static void validateLength(
            String value,
            int maximum,
            String field) {
        if (value != null && value.length() > maximum) {
            throw new IllegalArgumentException(field + " is too long");
        }
    }
}
