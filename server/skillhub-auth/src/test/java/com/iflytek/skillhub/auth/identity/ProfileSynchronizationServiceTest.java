package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserProfileFieldName;
import com.iflytek.skillhub.domain.user.UserProfileFieldSource;
import com.iflytek.skillhub.domain.user.UserProfileFieldSourceRepository;
import com.iflytek.skillhub.domain.user.UserProfileFieldSourceType;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class ProfileSynchronizationServiceTest {

    private static final Instant AUTHENTICATED_AT =
            Instant.parse("2026-07-30T08:00:00Z");
    private static final Instant UPDATED_AT =
            Instant.parse("2026-07-30T08:01:00Z");

    private UserProfileFieldSourceRepository sourceRepository;
    private ProfileSynchronizationService service;

    @BeforeEach
    void setUp() {
        sourceRepository =
                mock(UserProfileFieldSourceRepository.class);
        service = new ProfileSynchronizationService(
                sourceRepository,
                Clock.fixed(UPDATED_AT, ZoneOffset.UTC));
        when(sourceRepository.findByUserId(any()))
                .thenReturn(List.of());
        when(sourceRepository.save(
                any(UserProfileFieldSource.class)))
                .thenAnswer(invocation ->
                        invocation.getArgument(0));
    }

    @Test
    void defaultPolicyInitializesNewAccountAndRecordsProviderSources() {
        UserAccount user = new UserAccount(
                "usr_1",
                "usr_1",
                null,
                null);

        service.synchronize(
                user,
                assertion(EmailAssurance.VERIFIED),
                descriptor(ProfileSyncPolicy.defaults()),
                true);

        assertThat(user.getDisplayName()).isEqualTo("alice");
        assertThat(user.getEmail())
                .isEqualTo("alice@example.com");
        assertThat(user.getAvatarUrl())
                .isEqualTo(
                        "https://avatars.example/alice.png");
        ArgumentCaptor<UserProfileFieldSource> sources =
                ArgumentCaptor.forClass(
                        UserProfileFieldSource.class);
        verify(sourceRepository,
                org.mockito.Mockito.times(3))
                .save(sources.capture());
        assertThat(sources.getAllValues())
                .allSatisfy(source -> {
                    assertThat(source.getSourceType())
                            .isEqualTo(
                                    UserProfileFieldSourceType
                                            .PROVIDER);
                    assertThat(source.getProviderCode())
                            .isEqualTo("github");
                    assertThat(source.getLastSynchronizedAt())
                            .isEqualTo(AUTHENTICATED_AT);
                    assertThat(source.getUpdatedAt())
                            .isEqualTo(UPDATED_AT);
                });
    }

    @Test
    void preserveLocalDoesNotOverwriteUserMaintainedFields() {
        UserAccount user = new UserAccount(
                "usr_1",
                "local name",
                "local@example.com",
                "https://local.example/avatar.png");
        when(sourceRepository.findByUserId("usr_1"))
                .thenReturn(List.of(
                        local(
                                UserProfileFieldName.DISPLAY_NAME,
                                UserProfileFieldSourceType.USER),
                        local(
                                UserProfileFieldName.EMAIL,
                                UserProfileFieldSourceType.ADMIN),
                        local(
                                UserProfileFieldName.AVATAR_URL,
                                UserProfileFieldSourceType
                                        .LEGACY_LOCAL)));

        service.synchronize(
                user,
                assertion(EmailAssurance.VERIFIED),
                descriptor(new ProfileSyncPolicy(
                        ProfileSyncMode.PRESERVE_LOCAL,
                        ProfileSyncMode.PRESERVE_LOCAL,
                        ProfileSyncMode.PRESERVE_LOCAL)),
                false);

        assertThat(user.getDisplayName())
                .isEqualTo("local name");
        assertThat(user.getEmail())
                .isEqualTo("local@example.com");
        assertThat(user.getAvatarUrl())
                .isEqualTo(
                        "https://local.example/avatar.png");
        verify(sourceRepository, never()).save(any());
    }

    @Test
    void preserveLocalAllowsSameProviderToRefreshItsOwnField() {
        UserAccount user = new UserAccount(
                "usr_1",
                "old provider name",
                null,
                null);
        UserProfileFieldSource source =
                UserProfileFieldSource.provider(
                        "usr_1",
                        UserProfileFieldName.DISPLAY_NAME,
                        "github",
                        com.iflytek.skillhub.domain.user
                                .UserProfileFieldAssurance
                                .PROVIDER_ASSERTED,
                        AUTHENTICATED_AT.minusSeconds(60),
                        UPDATED_AT.minusSeconds(60));
        when(sourceRepository.findByUserId("usr_1"))
                .thenReturn(List.of(source));

        service.synchronize(
                user,
                assertion(EmailAssurance.UNVERIFIED),
                descriptor(new ProfileSyncPolicy(
                        ProfileSyncMode.PRESERVE_LOCAL,
                        ProfileSyncMode.NEVER,
                        ProfileSyncMode.NEVER)),
                false);

        assertThat(user.getDisplayName()).isEqualTo("alice");
        assertThat(source.getLastSynchronizedAt())
                .isEqualTo(AUTHENTICATED_AT);
        verify(sourceRepository).save(source);
    }

    @Test
    void fillIfEmptyIgnoresUnverifiedProviderEmail() {
        UserAccount user = new UserAccount(
                "usr_1",
                "local",
                null,
                null);
        when(sourceRepository.findByUserId("usr_1"))
                .thenReturn(List.of(local(
                        UserProfileFieldName.DISPLAY_NAME,
                        UserProfileFieldSourceType.USER)));

        service.synchronize(
                user,
                assertion(EmailAssurance.UNVERIFIED),
                descriptor(new ProfileSyncPolicy(
                        ProfileSyncMode.NEVER,
                        ProfileSyncMode.FILL_IF_EMPTY,
                        ProfileSyncMode.NEVER)),
                false);

        assertThat(user.getEmail()).isNull();
        verify(sourceRepository, never()).save(any());
    }

    @Test
    void initialOnlyDoesNotRefreshReturningAccount() {
        UserAccount user = new UserAccount(
                "usr_1",
                "initial name",
                "initial@example.com",
                "https://initial.example/avatar.png");
        when(sourceRepository.findByUserId("usr_1"))
                .thenReturn(List.of(
                        local(
                                UserProfileFieldName.DISPLAY_NAME,
                                UserProfileFieldSourceType.USER),
                        local(
                                UserProfileFieldName.EMAIL,
                                UserProfileFieldSourceType.USER),
                        local(
                                UserProfileFieldName.AVATAR_URL,
                                UserProfileFieldSourceType.USER)));

        service.synchronize(
                user,
                assertion(EmailAssurance.VERIFIED),
                descriptor(new ProfileSyncPolicy(
                        ProfileSyncMode.INITIAL_ONLY,
                        ProfileSyncMode.INITIAL_ONLY,
                        ProfileSyncMode.INITIAL_ONLY)),
                false);

        assertThat(user.getDisplayName())
                .isEqualTo("initial name");
        assertThat(user.getEmail())
                .isEqualTo("initial@example.com");
        assertThat(user.getAvatarUrl())
                .isEqualTo(
                        "https://initial.example/avatar.png");
        verify(sourceRepository, never()).save(any());
    }

    @Test
    void returningAccountBackfillsSourceGapsFromRollbackWindow() {
        UserAccount user = new UserAccount(
                "usr_1",
                "legacy name",
                "legacy@example.com",
                null);

        service.synchronize(
                user,
                assertion(EmailAssurance.VERIFIED),
                descriptor(ProfileSyncPolicy.defaults()),
                false);

        assertThat(user.getDisplayName())
                .isEqualTo("legacy name");
        assertThat(user.getEmail())
                .isEqualTo("legacy@example.com");
        assertThat(user.getAvatarUrl())
                .isEqualTo(
                        "https://avatars.example/alice.png");
        ArgumentCaptor<UserProfileFieldSource> sources =
                ArgumentCaptor.forClass(
                        UserProfileFieldSource.class);
        verify(sourceRepository,
                org.mockito.Mockito.times(3))
                .save(sources.capture());
        assertThat(sources.getAllValues())
                .extracting(
                        UserProfileFieldSource::getFieldName,
                        UserProfileFieldSource::getSourceType)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple(
                                "displayName",
                                UserProfileFieldSourceType
                                        .LEGACY_LOCAL),
                        org.assertj.core.groups.Tuple.tuple(
                                "email",
                                UserProfileFieldSourceType
                                        .LEGACY_LOCAL),
                        org.assertj.core.groups.Tuple.tuple(
                                "avatarUrl",
                                UserProfileFieldSourceType
                                        .PROVIDER));
    }

    @Test
    void providerAuthoritativeExplicitlyOverwritesLocalValue() {
        UserAccount user = new UserAccount(
                "usr_1",
                "local name",
                null,
                null);
        when(sourceRepository.findByUserId("usr_1"))
                .thenReturn(List.of(local(
                        UserProfileFieldName.DISPLAY_NAME,
                        UserProfileFieldSourceType.USER)));

        service.synchronize(
                user,
                assertion(EmailAssurance.UNVERIFIED),
                descriptor(new ProfileSyncPolicy(
                        ProfileSyncMode.PROVIDER_AUTHORITATIVE,
                        ProfileSyncMode.NEVER,
                        ProfileSyncMode.NEVER)),
                false);

        assertThat(user.getDisplayName()).isEqualTo("alice");
        ArgumentCaptor<UserProfileFieldSource> source =
                ArgumentCaptor.forClass(
                        UserProfileFieldSource.class);
        verify(sourceRepository).save(source.capture());
        assertThat(source.getValue().getSourceType())
                .isEqualTo(UserProfileFieldSourceType.PROVIDER);
        assertThat(source.getValue().getProviderCode())
                .isEqualTo("github");
    }

    @Test
    void neverUsesNeutralFallbackForRequiredDisplayName() {
        UserAccount user = new UserAccount(
                "usr_1",
                "usr_1",
                null,
                null);

        service.synchronize(
                user,
                assertion(EmailAssurance.VERIFIED),
                descriptor(new ProfileSyncPolicy(
                        ProfileSyncMode.NEVER,
                        ProfileSyncMode.NEVER,
                        ProfileSyncMode.NEVER)),
                true);

        assertThat(user.getDisplayName()).isEqualTo("usr_1");
        ArgumentCaptor<UserProfileFieldSource> source =
                ArgumentCaptor.forClass(
                        UserProfileFieldSource.class);
        verify(sourceRepository).save(source.capture());
        assertThat(source.getValue().getSourceType())
                .isEqualTo(
                        UserProfileFieldSourceType.LEGACY_LOCAL);
        assertThat(source.getValue().getProviderCode()).isNull();
    }

    private static UserProfileFieldSource local(
            UserProfileFieldName field,
            UserProfileFieldSourceType sourceType) {
        return UserProfileFieldSource.local(
                "usr_1",
                field,
                sourceType,
                UPDATED_AT.minusSeconds(60));
    }

    private static IdentityAssertion assertion(
            EmailAssurance emailAssurance) {
        return new IdentityAssertion(
                new ProviderReference(
                        "github",
                        "oauth2-github",
                        "https://github.com"),
                new ExternalSubject(
                        "github_user_id",
                        "123456"),
                Set.of(),
                new ExternalProfile(
                        "alice",
                        Optional.of(new EmailClaim(
                                "alice@example.com",
                                emailAssurance)),
                        Optional.of(URI.create(
                                "https://avatars.example/alice.png"))),
                Map.of(),
                new AuthenticationEvidence(
                        "oauth2-github",
                        AUTHENTICATED_AT,
                        Set.of("oauth2_authorization_code")));
    }

    private static ProviderDescriptor descriptor(
            ProfileSyncPolicy profileSyncPolicy) {
        return new ProviderDescriptor(
                "github",
                "oauth2-github",
                "https://github.com",
                "GitHub",
                "github_user_id",
                "github_user_id",
                Map.of(
                        "github_user_id",
                        SubjectCanonicalizer.DECIMAL),
                List.of("login"),
                List.of("email"),
                List.of("avatar_url"),
                EmailAssurance.VERIFIED,
                ProvisioningMode.AUTO,
                profileSyncPolicy);
    }
}
