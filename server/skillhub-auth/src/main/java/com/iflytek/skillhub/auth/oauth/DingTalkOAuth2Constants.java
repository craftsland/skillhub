package com.iflytek.skillhub.auth.oauth;

import java.util.List;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/** Shared protocol constants for the native DingTalk OAuth2 adapter. */
public final class DingTalkOAuth2Constants {

    public static final String REGISTRATION_ID = "dingtalk";
    public static final String AUTHORIZATION_SCOPE = "openid";
    public static final String AUTHORIZATION_URI =
            "https://login.dingtalk.com/oauth2/auth";
    public static final String TOKEN_URI =
            "https://api.dingtalk.com/v1.0/oauth2/userAccessToken";
    public static final String USER_INFO_URI =
            "https://api.dingtalk.com/v1.0/contact/users/me";
    public static final String ACCESS_TOKEN_HEADER =
            "x-acs-dingtalk-access-token";
    public static final String SUBJECT_ATTRIBUTE = "dingtalkSubject";
    public static final String UNION_ID_ATTRIBUTE = "unionId";
    public static final String OPEN_ID_ATTRIBUTE = "openId";
    public static final String USER_ID_ATTRIBUTE = "userId";
    public static final String NICK_ATTRIBUTE = "nick";
    public static final String NAME_ATTRIBUTE = "name";
    public static final String EMAIL_ATTRIBUTE = "email";
    public static final String AVATAR_ATTRIBUTE = "avatarUrl";
    static final List<String> SUBJECT_CLAIM_NAMES = List.of(
            UNION_ID_ATTRIBUTE,
            OPEN_ID_ATTRIBUTE,
            USER_ID_ATTRIBUTE);

    /** Returns whether a registration exactly matches the server-owned flow. */
    public static boolean hasTrustedRegistration(
            ClientRegistration registration) {
        if (registration == null
                || !REGISTRATION_ID.equals(registration.getRegistrationId())
                || !AuthorizationGrantType.AUTHORIZATION_CODE.equals(
                        registration.getAuthorizationGrantType())) {
            return false;
        }
        var details = registration.getProviderDetails();
        var userInfo = details.getUserInfoEndpoint();
        return AUTHORIZATION_URI.equals(details.getAuthorizationUri())
                && TOKEN_URI.equals(details.getTokenUri())
                && userInfo != null
                && USER_INFO_URI.equals(userInfo.getUri())
                && SUBJECT_ATTRIBUTE.equals(
                        userInfo.getUserNameAttributeName());
    }

    private DingTalkOAuth2Constants() {
    }
}
