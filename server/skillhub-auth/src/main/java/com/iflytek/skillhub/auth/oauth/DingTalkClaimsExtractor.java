package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/** Maps a verified DingTalk user-info response into unified identity facts. */
@Component
public class DingTalkClaimsExtractor implements OAuthClaimsExtractor {

    static final String NICK_ATTRIBUTE = "dingtalk_nick";
    static final String NAME_ATTRIBUTE = "dingtalk_name";
    static final String EMAIL_ATTRIBUTE = "dingtalk_email";
    static final String AVATAR_ATTRIBUTE = "dingtalk_avatar_url";

    private static final String UNION_SUBJECT_TYPE =
            "dingtalk_union_id";
    private static final String OPEN_SUBJECT_TYPE =
            "dingtalk_open_id";
    private static final String USER_SUBJECT_TYPE =
            "dingtalk_user_id";

    @Override
    public String getProvider() {
        return DingTalkOAuth2Constants.REGISTRATION_ID;
    }

    @Override
    public ProviderAuthenticationResult extract(
            OAuth2UserRequest request,
            OAuth2User oauthUser) {
        Map<String, Object> source = oauthUser.getAttributes();
        String unionId = requireString(
                source,
                DingTalkOAuth2Constants.UNION_ID_ATTRIBUTE);

        List<SubjectCandidate> aliases = new ArrayList<>();
        addAlias(
                aliases,
                OPEN_SUBJECT_TYPE,
                source.get(DingTalkOAuth2Constants.OPEN_ID_ATTRIBUTE));
        addAlias(
                aliases,
                USER_SUBJECT_TYPE,
                source.get(DingTalkOAuth2Constants.USER_ID_ATTRIBUTE));

        Map<String, List<ProviderAttributeValue>> attributes =
                new LinkedHashMap<>();
        put(
                attributes,
                NICK_ATTRIBUTE,
                source.get(DingTalkOAuth2Constants.NICK_ATTRIBUTE));
        put(
                attributes,
                NAME_ATTRIBUTE,
                source.get(DingTalkOAuth2Constants.NAME_ATTRIBUTE));
        put(
                attributes,
                EMAIL_ATTRIBUTE,
                source.get(DingTalkOAuth2Constants.EMAIL_ATTRIBUTE));
        put(
                attributes,
                AVATAR_ATTRIBUTE,
                source.get(DingTalkOAuth2Constants.AVATAR_ATTRIBUTE));

        return new ProviderAuthenticationResult(
                new SubjectCandidate(UNION_SUBJECT_TYPE, unionId),
                aliases,
                attributes,
                new ProtocolAuthenticationEvidence(
                        "dingtalk-oauth2",
                        request.getAccessToken().getIssuedAt(),
                        Set.of("oauth2_authorization_code")));
    }

    static String requireUnionId(Map<String, Object> attributes) {
        return requireString(
                attributes,
                DingTalkOAuth2Constants.UNION_ID_ATTRIBUTE);
    }

    private static String requireString(
            Map<String, Object> attributes,
            String key) {
        String value = stringValue(attributes.get(key));
        if (value == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            "missing_stable_subject",
                            "DingTalk unionId is required",
                            null));
        }
        return value;
    }

    private static void addAlias(
            List<SubjectCandidate> aliases,
            String type,
            Object rawValue) {
        String value = stringValue(rawValue);
        if (value != null) {
            aliases.add(new SubjectCandidate(type, value));
        }
    }

    private static void put(
            Map<String, List<ProviderAttributeValue>> attributes,
            String key,
            Object rawValue) {
        String value = stringValue(rawValue);
        if (value == null) {
            return;
        }
        attributes.put(
                key,
                List.of(new ProviderAttributeValue(
                        value,
                        ProviderAttributeTrust.ASSERTED)));
    }

    private static String stringValue(Object rawValue) {
        if (!(rawValue instanceof String value)
                || value.isBlank()
                || !value.equals(value.strip())) {
            return null;
        }
        return value;
    }
}
