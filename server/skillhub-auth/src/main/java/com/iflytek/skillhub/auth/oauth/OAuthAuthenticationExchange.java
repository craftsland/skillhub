package com.iflytek.skillhub.auth.oauth;

import java.util.Objects;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Verified Spring Security OAuth exchange consumed by an OAuth claims adapter.
 */
public record OAuthAuthenticationExchange(
        OAuth2UserRequest request,
        OAuth2User user
) {
    public OAuthAuthenticationExchange {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(user, "user");
    }
}
