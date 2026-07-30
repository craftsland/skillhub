package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class OAuthAdapterBoundaryTest {

    private static final List<Class<?>> ADAPTERS = List.of(
            OAuthClaimsExtractor.class,
            GitHubClaimsExtractor.class,
            GitLabClaimsExtractor.class,
            CustomOAuth2UserService.class,
            CustomOidcUserService.class);

    private static final List<String> FORBIDDEN_DEPENDENCIES = List.of(
            "com/iflytek/skillhub/auth/identity/DefaultResolvedProviderHandle",
            "com/iflytek/skillhub/auth/identity/IdentityAssertionFactory",
            "com/iflytek/skillhub/auth/identity/PlatformPrincipalFactory",
            "com/iflytek/skillhub/auth/session/PlatformSessionService",
            "com/iflytek/skillhub/auth/repository/IdentityBindingRepository",
            "com/iflytek/skillhub/domain/user/UserAccountRepository",
            "jakarta/persistence/",
            "org/springframework/data/jpa/");

    @Test
    void adaptersCannotReachCoreFactoriesSessionsOrPersistence() throws IOException {
        for (Class<?> adapter : ADAPTERS) {
            String bytecode = classFileConstants(adapter);
            assertThat(FORBIDDEN_DEPENDENCIES)
                    .as("forbidden bytecode dependencies of %s", adapter.getName())
                    .noneMatch(bytecode::contains);
        }
    }

    private static String classFileConstants(Class<?> type) throws IOException {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream input = type.getResourceAsStream(resource)) {
            assertThat(input)
                    .as("compiled class resource for %s", type.getName())
                    .isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }
}
