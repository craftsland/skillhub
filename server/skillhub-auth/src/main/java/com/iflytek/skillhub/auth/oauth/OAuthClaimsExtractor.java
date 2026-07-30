package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.provider.BrowserAuthenticationAdapter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Strategy interface for converting provider-specific OAuth user payloads into normalized claims.
 */
public interface OAuthClaimsExtractor
        extends BrowserAuthenticationAdapter<OAuthAuthenticationExchange> {
    String getProvider();
    ProviderAuthenticationResult extract(
            OAuth2UserRequest request,
            OAuth2User oAuth2User);

    @Override
    default ProviderAuthenticationResult authenticate(
            OAuthAuthenticationExchange exchange) {
        return extract(exchange.request(), exchange.user());
    }
}
