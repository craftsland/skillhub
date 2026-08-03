package com.iflytek.skillhub.auth.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/** Selects the trusted user-info transport for each browser registration. */
@Component
final class ProviderAwareOAuth2UserService
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User>
            standardDelegate;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User>
            dingTalkDelegate;

    @Autowired
    ProviderAwareOAuth2UserService(
            @Qualifier("dingTalkOAuth2UserService")
            OAuth2UserService<OAuth2UserRequest, OAuth2User>
                    dingTalkDelegate) {
        this(new DefaultOAuth2UserService(), dingTalkDelegate);
    }

    ProviderAwareOAuth2UserService(
            OAuth2UserService<OAuth2UserRequest, OAuth2User>
                    standardDelegate,
            OAuth2UserService<OAuth2UserRequest, OAuth2User>
                    dingTalkDelegate) {
        this.standardDelegate = standardDelegate;
        this.dingTalkDelegate = dingTalkDelegate;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) {
        if (request != null
                && DingTalkOAuth2Constants.REGISTRATION_ID.equals(
                request.getClientRegistration().getRegistrationId())) {
            return dingTalkDelegate.loadUser(request);
        }
        return standardDelegate.loadUser(request);
    }
}
