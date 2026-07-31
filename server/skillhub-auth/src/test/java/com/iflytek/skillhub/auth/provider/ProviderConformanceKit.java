package com.iflytek.skillhub.auth.provider;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

/**
 * Reusable assertions for trusted in-tree provider adapters.
 *
 * <p>Each adapter test supplies deterministic protocol fixtures and invokes
 * the relevant capability assertion. Network error classification and timeout
 * cases remain protocol-specific tests beside the adapter.</p>
 */
public final class ProviderConformanceKit {

    private static final List<String> FORBIDDEN_DEPENDENCIES = List.of(
            "com/iflytek/skillhub/auth/rbac/PlatformPrincipal",
            "com/iflytek/skillhub/auth/identity/IdentityAssertionFactory",
            "com/iflytek/skillhub/auth/identity/PlatformPrincipalFactory",
            "com/iflytek/skillhub/auth/session/PlatformSessionService",
            "com/iflytek/skillhub/auth/repository/",
            "com/iflytek/skillhub/domain/user/UserAccount",
            "com/iflytek/skillhub/domain/namespace/",
            "jakarta/persistence/",
            "jakarta/servlet/",
            "javax/servlet/",
            "org/springframework/data/jpa/",
            "org/springframework/security/core/context/",
            "org/springframework/security/web/context/");

    private ProviderConformanceKit() {
    }

    public static <T> ProviderAuthenticationResult verifyBrowser(
            BrowserAuthenticationAdapter<T> adapter,
            T fixture) {
        ProviderInstanceDefinition provider =
                verifyDefinition(adapter.provider(), adapter.provider());
        ProviderAuthenticationResult result =
                adapter.authenticate(fixture);
        verifyResult(provider, result);
        return result;
    }

    public static ProviderAuthenticationResult verifyCredential(
            CredentialAuthenticationAdapter adapter,
            CredentialAuthenticationRequest fixture) {
        ProviderInstanceDefinition provider =
                verifyDefinition(adapter.provider(), adapter.provider());
        ProviderAuthenticationResult result =
                adapter.authenticate(fixture);
        verifyResult(provider, result);
        return result;
    }

    public static ProviderAuthenticationResult verifyPassive(
            PassiveAuthenticationAdapter adapter,
            PassiveAuthenticationRequest fixture) {
        ProviderInstanceDefinition provider =
                verifyDefinition(adapter.provider(), adapter.provider());
        Optional<ProviderAuthenticationResult> authentication =
                adapter.authenticate(fixture);
        assertThat(authentication)
                .as("positive passive fixture must return an Optional")
                .isNotNull()
                .isPresent();
        ProviderAuthenticationResult result = authentication.orElseThrow();
        verifyResult(provider, result);
        return result;
    }

    /**
     * Verifies stable subjects from two equivalent, independently valid
     * protocol fixtures. Passive adapters should use distinct nonces or
     * assertions so this check does not conflict with replay protection.
     */
    public static void verifyStableSubjects(
            ProviderInstanceDefinition provider,
            ProviderAuthenticationResult first,
            ProviderAuthenticationResult second) {
        verifyResult(provider, first);
        verifyResult(provider, second);
        assertThat(second.primarySubject())
                .as("equivalent fixtures must produce a stable primary subject")
                .isEqualTo(first.primarySubject());
        assertThat(second.alternateSubjects())
                .as("equivalent fixtures must produce stable alternate subjects")
                .isEqualTo(first.alternateSubjects());
    }

    public static void verifyResult(
            ProviderInstanceDefinition provider,
            ProviderAuthenticationResult result) {
        assertThat(result).isNotNull();
        assertThat(result.evidence().protocol())
                .isEqualTo(provider.protocol());
        assertAllowedSubject(provider, result.primarySubject());
        for (SubjectCandidate alternate : result.alternateSubjects()) {
            assertAllowedSubject(provider, alternate);
        }
        assertEmailAssurance(provider, result);
    }

    public static void verifyAdapterBoundary(Class<?>... adapterClasses)
            throws IOException {
        for (Class<?> adapterClass : adapterClasses) {
            String bytecode = classFileConstants(adapterClass);
            assertThat(FORBIDDEN_DEPENDENCIES)
                    .as(
                            "forbidden dependencies of %s",
                            adapterClass.getName())
                    .noneMatch(bytecode::contains);
        }
    }

    private static ProviderInstanceDefinition verifyDefinition(
            ProviderInstanceDefinition first,
            ProviderInstanceDefinition second) {
        assertThat(first)
                .as("provider definition is required")
                .isNotNull();
        assertThat(second)
                .as("provider definition must be deterministic")
                .isEqualTo(first);
        return first;
    }

    private static void assertAllowedSubject(
            ProviderInstanceDefinition provider,
            SubjectCandidate subject) {
        assertThat(provider.subjectNormalizations())
                .as("subject type must be declared by the provider")
                .containsKey(subject.type());
        assertThat(subject.value()).isNotBlank();
    }

    private static void assertEmailAssurance(
            ProviderInstanceDefinition provider,
            ProviderAuthenticationResult result) {
        for (String attribute : provider.emailAttributes()) {
            for (ProviderAttributeValue value : result.attributes()
                    .getOrDefault(attribute, List.of())) {
                EmailAssurance asserted =
                        assurance(value.trust());
                assertThat(asserted.ordinal())
                        .as(
                                "email assurance for attribute %s",
                                attribute)
                        .isLessThanOrEqualTo(
                                provider.emailAssuranceLimit().ordinal());
            }
        }
    }

    private static EmailAssurance assurance(
            ProviderAttributeTrust trust) {
        return switch (trust) {
            case UNVERIFIED -> EmailAssurance.UNVERIFIED;
            case ASSERTED -> EmailAssurance.PROVIDER_ASSERTED;
            case VERIFIED -> EmailAssurance.VERIFIED;
        };
    }

    private static String classFileConstants(Class<?> type)
            throws IOException {
        String resource = "/"
                + type.getName().replace('.', '/')
                + ".class";
        try (InputStream input =
                type.getResourceAsStream(resource)) {
            assertThat(input)
                    .as(
                            "compiled class resource for %s",
                            type.getName())
                    .isNotNull();
            return new String(
                    input.readAllBytes(),
                    StandardCharsets.ISO_8859_1);
        }
    }
}
