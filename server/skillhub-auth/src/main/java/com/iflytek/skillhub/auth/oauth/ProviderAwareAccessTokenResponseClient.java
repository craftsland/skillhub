package com.iflytek.skillhub.auth.oauth;

import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/** Selects the trusted token exchange for each browser registration. */
@Component
public final class ProviderAwareAccessTokenResponseClient
        implements OAuth2AccessTokenResponseClient<
                OAuth2AuthorizationCodeGrantRequest> {

    private final OAuth2AccessTokenResponseClient<
                    OAuth2AuthorizationCodeGrantRequest> standardDelegate;
    private final OAuth2AccessTokenResponseClient<
            OAuth2AuthorizationCodeGrantRequest> dingTalkDelegate;

    @Autowired
    public ProviderAwareAccessTokenResponseClient(
            @Qualifier("dingTalkTokenResponseClient")
            OAuth2AccessTokenResponseClient<
                    OAuth2AuthorizationCodeGrantRequest> dingTalkDelegate) {
        this(
                new DefaultAuthorizationCodeTokenResponseClient(),
                dingTalkDelegate);
    }

    ProviderAwareAccessTokenResponseClient(
            OAuth2AccessTokenResponseClient<
                    OAuth2AuthorizationCodeGrantRequest> standardDelegate,
            OAuth2AccessTokenResponseClient<
                    OAuth2AuthorizationCodeGrantRequest> dingTalkDelegate) {
        this.standardDelegate = standardDelegate;
        this.dingTalkDelegate = dingTalkDelegate;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(
            OAuth2AuthorizationCodeGrantRequest request) {
        if (request != null
                && DingTalkOAuth2Constants.REGISTRATION_ID.equals(
                request.getClientRegistration().getRegistrationId())) {
            return dingTalkDelegate.getTokenResponse(request);
        }
        return standardDelegate.getTokenResponse(request);
    }
}
