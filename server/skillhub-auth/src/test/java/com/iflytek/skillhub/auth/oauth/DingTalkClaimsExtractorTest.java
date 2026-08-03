package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

class DingTalkClaimsExtractorTest {

    @Test
    void mapsStableUnionIdAndSameResponseAliasesToUnifiedIdentityFacts() {
        DingTalkClaimsExtractor extractor = new DingTalkClaimsExtractor();

        ProviderAuthenticationResult result = extractor.extract(
                userRequest(),
                new DefaultOAuth2User(
                        List.of(),
                        Map.of(
                                "unionId", "union-123",
                                "openId", "open-456",
                                "userId", "user-789",
                                "nick", "Alice",
                                "email", "alice@example.com",
                                "avatarUrl", "https://example.com/alice.png"),
                        "unionId"));

        assertThat(result.primarySubject())
                .isEqualTo(new SubjectCandidate(
                        "dingtalk_union_id", "union-123"));
        assertThat(result.alternateSubjects()).containsExactly(
                new SubjectCandidate("dingtalk_open_id", "open-456"),
                new SubjectCandidate("dingtalk_user_id", "user-789"));
        assertThat(result.attributes().get("dingtalk_email"))
                .singleElement()
                .satisfies(value -> {
                    assertThat(value.value()).isEqualTo("alice@example.com");
                    assertThat(value.trust())
                            .isEqualTo(ProviderAttributeTrust.ASSERTED);
                });
        assertThat(result.evidence().protocol())
                .isEqualTo("dingtalk-oauth2");
    }

    @Test
    void rejectsResponseWithoutStableUnionIdEvenWhenOtherIdsExist() {
        DingTalkClaimsExtractor extractor = new DingTalkClaimsExtractor();
        DefaultOAuth2User upstreamUser = new DefaultOAuth2User(
                List.of(),
                Map.of(
                        "openId", "open-456",
                        "userId", "user-789"),
                "openId");

        assertThatThrownBy(() ->
                extractor.extract(userRequest(), upstreamUser))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo("missing_stable_subject"));
    }

    private static OAuth2UserRequest userRequest() {
        ClientRegistration registration =
                ClientRegistration.withRegistrationId("dingtalk")
                        .clientId("client-id")
                        .clientSecret("client-secret")
                        .authorizationGrantType(
                                AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri(
                                "{baseUrl}/login/oauth2/code/{registrationId}")
                        .scope("openid")
                        .authorizationUri(
                                DingTalkOAuth2Constants.AUTHORIZATION_URI)
                        .tokenUri(DingTalkOAuth2Constants.TOKEN_URI)
                        .userInfoUri(
                                DingTalkOAuth2Constants.USER_INFO_URI)
                        .userNameAttributeName("dingtalkSubject")
                        .clientName("DingTalk")
                        .build();
        Instant issuedAt = Instant.parse("2026-08-03T00:00:00Z");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "token-123",
                issuedAt,
                issuedAt.plusSeconds(3600));
        return new OAuth2UserRequest(registration, accessToken);
    }
}
