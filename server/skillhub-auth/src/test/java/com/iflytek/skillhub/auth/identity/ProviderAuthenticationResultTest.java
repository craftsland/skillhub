package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ProviderAuthenticationResultTest {

    @Test
    void rejectsSecretBearingAttributesIncludingNamespacedKeys() {
        for (String key : List.of(
                "token",
                "access_token",
                "oauth.auth_token",
                "oidc.refresh_token",
                "upstream:password",
                "session.cookie",
                "cas:ticket",
                "raw_response",
                "clientSecret",
                "oauth.clientSecret",
                "clientsecret",
                "apiKey",
                "oauthApiKey",
                "accessToken",
                "refreshToken",
                "idToken",
                "privateKey",
                "clientAssertion",
                "rawResponse")) {
            assertThatThrownBy(() -> new ProviderAuthenticationResult(
                    new SubjectCandidate("oidc_sub", "subject-1"),
                    List.of(),
                    Map.of(
                            key,
                            List.of(new ProviderAttributeValue(
                                    "secret",
                                    ProviderAttributeTrust.ASSERTED))),
                    new ProtocolAuthenticationEvidence(
                            "oidc",
                            Instant.parse("2026-07-30T00:00:00Z"),
                            Set.of("authorization_code"))))
                    .as("attribute key %s", key)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(
                            "Sensitive provider attributes");
        }
    }
}
