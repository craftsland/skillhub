package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Strategy interface for converting provider-specific OAuth user payloads into normalized claims.
 *
 * <p>The Spring Security client registration remains the registered browser
 * provider. This extractor only maps its already verified exchange and is not
 * independently routable.</p>
 */
public interface OAuthClaimsExtractor {
    String getProvider();
    ProviderAuthenticationResult extract(
            OAuth2UserRequest request,
            OAuth2User oAuth2User);

    default ProviderAuthenticationResult authenticate(
            OAuthAuthenticationExchange exchange) {
        return extract(exchange.request(), exchange.user());
    }
}
