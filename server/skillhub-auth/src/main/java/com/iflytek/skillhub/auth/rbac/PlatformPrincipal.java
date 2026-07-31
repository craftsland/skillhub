package com.iflytek.skillhub.auth.rbac;

import java.io.Serializable;
import java.security.Principal;
import java.util.Set;

/**
 * Serializable authenticated principal shared across session, OAuth, and API-token flows.
 */
public record PlatformPrincipal(
    String userId,
    String displayName,
    String email,
    String avatarUrl,
    String oauthProvider,
    Set<String> platformRoles
) implements Principal, Serializable {

    /**
     * Spring Session indexes authenticated sessions by
     * {@link Principal#getName()}. The immutable platform user ID is the only
     * stable name across local, OAuth, OIDC, CAS, and credential providers.
     */
    @Override
    public String getName() {
        return userId;
    }
}
