package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ProviderAuthorityFingerprintTest {

    @Test
    void matchesFrozenOidcVector() {
        assertThat(ProviderAuthorityFingerprint.sha256(
                "oidc",
                "https://id.example.com"))
                .isEqualTo(
                        "4d12ea0e7a413a716adf2acf2434f2a0642e74abcd3e3273bad170127c53fd00");
    }

    @Test
    void matchesFrozenGithubVector() {
        assertThat(ProviderAuthorityFingerprint.sha256(
                "oauth2-github",
                "https://github.com"))
                .isEqualTo(
                        "b2a93d58465e3de9e8b6cd127ba18425ae0f80c49c85f18f76086832923ca619");
    }

    @Test
    void usesExactAuthorityBytesWithoutImplicitNormalization() {
        assertThat(ProviderAuthorityFingerprint.sha256(
                "oidc",
                "https://id.example.com/"))
                .isNotEqualTo(ProviderAuthorityFingerprint.sha256(
                        "oidc",
                        "https://id.example.com"));
    }
}
