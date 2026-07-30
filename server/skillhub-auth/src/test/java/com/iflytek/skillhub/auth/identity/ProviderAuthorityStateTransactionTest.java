package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class ProviderAuthorityStateTransactionTest {

    private static final ProviderDescriptor GITHUB = githubDescriptor();
    private static final String FINGERPRINT =
            "b2a93d58465e3de9e8b6cd127ba18425ae0f80c49c85f18f76086832923ca619";
    private static final Instant NOW = Instant.parse("2026-07-30T08:30:00Z");

    private IdentityProviderStateRepository stateRepository;
    private IdentityBindingRepository bindingRepository;
    private AuditLogService auditLogService;
    private ProviderAuthorityStateTransaction transaction;

    @BeforeEach
    void setUp() {
        stateRepository = mock(IdentityProviderStateRepository.class);
        bindingRepository = mock(IdentityBindingRepository.class);
        auditLogService = mock(AuditLogService.class);
        transaction = new ProviderAuthorityStateTransaction(
                stateRepository,
                bindingRepository,
                auditLogService);
    }

    @Test
    void insertsReadyPinForProviderWithoutLegacyBindingsAndRereadsIt() {
        IdentityProviderState ready = IdentityProviderState.ready(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT,
                NOW);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.empty(), Optional.of(ready));
        when(bindingRepository.existsByProviderCode("github")).thenReturn(false);
        when(stateRepository.insertReady(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT)).thenReturn(1);

        AuthorityLockEvaluation evaluation = transaction.pin(GITHUB, FINGERPRINT);

        assertThat(evaluation.ready()).isTrue();
        InOrder order = inOrder(stateRepository);
        order.verify(stateRepository).findById("github");
        order.verify(stateRepository).insertReady(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT);
        order.verify(stateRepository).findById("github");
    }

    @Test
    void pinsLegacyProviderWithCompareAndSetBeforeReread() {
        IdentityProviderState legacy = IdentityProviderState.legacyUnpinned(
                "github",
                "oauth2-github",
                NOW);
        IdentityProviderState ready = IdentityProviderState.ready(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT,
                NOW);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.empty(), Optional.of(legacy), Optional.of(ready));
        when(bindingRepository.existsByProviderCode("github")).thenReturn(true);
        when(stateRepository.insertLegacyUnpinned(
                "github",
                "oauth2-github")).thenReturn(1);
        when(stateRepository.pinLegacy(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT)).thenReturn(1);

        AuthorityLockEvaluation evaluation = transaction.pin(GITHUB, FINGERPRINT);

        assertThat(evaluation.ready()).isTrue();
        InOrder order = inOrder(stateRepository);
        order.verify(stateRepository).findById("github");
        order.verify(stateRepository)
                .insertLegacyUnpinned("github", "oauth2-github");
        order.verify(stateRepository).findById("github");
        order.verify(stateRepository).pinLegacy(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT);
        order.verify(stateRepository).findById("github");
    }

    @Test
    void concurrentSameAuthorityConvergesOnPersistedReadyState() {
        IdentityProviderState ready = IdentityProviderState.ready(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT,
                NOW);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.empty(), Optional.of(ready));
        when(bindingRepository.existsByProviderCode("github")).thenReturn(false);
        when(stateRepository.insertReady(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT)).thenReturn(0);

        AuthorityLockEvaluation evaluation = transaction.pin(GITHUB, FINGERPRINT);

        assertThat(evaluation.ready()).isTrue();
        verify(stateRepository, never()).markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT);
    }

    @Test
    void changedAuthorityIsMarkedMismatchWithoutOverwritingPinnedValues() {
        IdentityProviderState pinned = IdentityProviderState.ready(
                "github",
                "oauth2-github",
                "https://github.example",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                NOW);
        IdentityProviderState mismatch = IdentityProviderState.authorityMismatch(
                "github",
                "oauth2-github",
                "https://github.example",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                NOW);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.of(pinned), Optional.of(mismatch));
        when(stateRepository.markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT)).thenReturn(1);

        AuthorityLockEvaluation evaluation = transaction.pin(GITHUB, FINGERPRINT);

        assertThat(evaluation.ready()).isFalse();
        assertThat(evaluation.state())
                .isEqualTo(IdentityProviderStatus.AUTHORITY_MISMATCH);
        assertThat(evaluation.persistedFingerprint())
                .isEqualTo(pinned.getAuthorityFingerprint());
        verify(stateRepository).markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT);
        verify(stateRepository, never()).pinLegacy(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT);
    }

    @Test
    void rereadsPersistedStateWhenReadyTouchLosesAuthorityRace() {
        IdentityProviderState cachedReady = IdentityProviderState.ready(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT,
                NOW);
        IdentityProviderState mismatch = IdentityProviderState.authorityMismatch(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT,
                NOW);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.of(cachedReady), Optional.of(mismatch));
        when(stateRepository.touchReady(
                "github",
                "oauth2-github",
                FINGERPRINT))
                .thenReturn(0);

        AuthorityLockEvaluation evaluation =
                transaction.pin(GITHUB, FINGERPRINT);

        assertThat(evaluation.ready()).isFalse();
        assertThat(evaluation.state())
                .isEqualTo(IdentityProviderStatus.AUTHORITY_MISMATCH);
        verify(stateRepository).touchReady(
                "github",
                "oauth2-github",
                FINGERPRINT);
        verify(stateRepository, never()).recoverSameAuthority(
                "github",
                "oauth2-github",
                FINGERPRINT);
    }

    @Test
    void mismatchIsStickyEvenAfterConfigurationReturnsToPinnedFingerprint() {
        IdentityProviderState mismatch = IdentityProviderState.authorityMismatch(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT,
                NOW);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.of(mismatch));

        AuthorityLockEvaluation evaluation = transaction.pin(GITHUB, FINGERPRINT);

        assertThat(evaluation.ready()).isFalse();
        assertThat(evaluation.state())
                .isEqualTo(IdentityProviderStatus.AUTHORITY_MISMATCH);
        verify(stateRepository, never()).recoverSameAuthority(
                "github",
                "oauth2-github",
                FINGERPRINT);
        verify(stateRepository, never()).markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT);
    }

    @Test
    void changedProtocolIsMismatchEvenIfStoredFingerprintWasTamperedToMatch() {
        IdentityProviderState pinned = IdentityProviderState.ready(
                "github",
                "oidc",
                "https://github.com",
                FINGERPRINT,
                NOW);
        IdentityProviderState mismatch = IdentityProviderState.authorityMismatch(
                "github",
                "oidc",
                "https://github.com",
                FINGERPRINT,
                NOW);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.of(pinned), Optional.of(mismatch));
        when(stateRepository.markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT)).thenReturn(1);

        AuthorityLockEvaluation evaluation = transaction.pin(GITHUB, FINGERPRINT);

        assertThat(evaluation.state())
                .isEqualTo(IdentityProviderStatus.AUTHORITY_MISMATCH);
        verify(stateRepository).markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT);
    }

    @Test
    void explicitRecoveryOnlySucceedsForThePersistedFingerprint() {
        IdentityProviderState recovered = IdentityProviderState.ready(
                "github",
                "oauth2-github",
                "https://github.com",
                FINGERPRINT,
                NOW);
        when(stateRepository.recoverSameAuthority(
                "github",
                "oauth2-github",
                FINGERPRINT)).thenReturn(1);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.of(recovered));

        IdentityProviderAuthorityRecoveryContext context =
                recoveryContext();
        SameAuthorityRecoveryEvaluation recovery =
                transaction.recoverSameAuthority(
                        GITHUB,
                        FINGERPRINT,
                        context);

        assertThat(recovery.recovered()).isTrue();
        assertThat(recovery.authority().ready()).isTrue();
        verify(stateRepository).recoverSameAuthority(
                "github",
                "oauth2-github",
                FINGERPRINT);
        verify(auditLogService).record(
                "admin",
                "PROVIDER_AUTHORITY_RECOVERED",
                "IDENTITY_PROVIDER",
                null,
                "req-123",
                "203.0.113.9",
                "SkillHub Browser",
                "{\"providerCode\":\"github\",\"protocol\":\"oauth2-github\",\"authorityFingerprint\":\""
                        + FINGERPRINT
                        + "\"}");
    }

    @Test
    void failedRecoveryDoesNotWriteMisleadingAudit() {
        IdentityProviderState mismatch =
                IdentityProviderState.authorityMismatch(
                        "github",
                        "oauth2-github",
                        "https://github.example",
                        "a".repeat(64),
                        NOW);
        when(stateRepository.recoverSameAuthority(
                "github",
                "oauth2-github",
                FINGERPRINT)).thenReturn(0);
        when(stateRepository.findById("github"))
                .thenReturn(Optional.of(mismatch));

        SameAuthorityRecoveryEvaluation recovery =
                transaction.recoverSameAuthority(
                        GITHUB,
                        FINGERPRINT,
                        recoveryContext());

        assertThat(recovery.recovered()).isFalse();
        assertThat(recovery.authority().state())
                .isEqualTo(IdentityProviderStatus.AUTHORITY_MISMATCH);
        verify(auditLogService, never()).record(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void readyStateWithDifferentFingerprintIsPersistedAsMismatch() {
        String differentFingerprint = "a".repeat(64);
        IdentityProviderState staleReady = IdentityProviderState.ready(
                "github",
                "oauth2-github",
                "https://github.example",
                differentFingerprint,
                NOW);
        IdentityProviderState mismatch =
                IdentityProviderState.authorityMismatch(
                        "github",
                        "oauth2-github",
                        "https://github.example",
                        differentFingerprint,
                        NOW);
        when(stateRepository.recoverSameAuthority(
                "github",
                "oauth2-github",
                FINGERPRINT)).thenReturn(0);
        when(stateRepository.findById("github"))
                .thenReturn(
                        Optional.of(staleReady),
                        Optional.of(mismatch));
        when(stateRepository.markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT)).thenReturn(1);

        SameAuthorityRecoveryEvaluation recovery =
                transaction.recoverSameAuthority(
                        GITHUB,
                        FINGERPRINT,
                        recoveryContext());

        assertThat(recovery.recovered()).isFalse();
        assertThat(recovery.authority().state())
                .isEqualTo(IdentityProviderStatus.AUTHORITY_MISMATCH);
        verify(stateRepository).markAuthorityMismatch(
                "github",
                "oauth2-github",
                FINGERPRINT);
        verify(auditLogService, never()).record(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    private static ProviderDescriptor githubDescriptor() {
        return new ProviderDescriptor(
                "github",
                "oauth2-github",
                "https://github.com",
                "GitHub",
                "github_user_id",
                java.util.Set.of("github_user_id"),
                SubjectCanonicalizer.DECIMAL,
                java.util.List.of("login"),
                java.util.List.of("email"),
                java.util.List.of("avatar_url"),
                EmailAssurance.VERIFIED);
    }

    private static IdentityProviderAuthorityRecoveryContext
            recoveryContext() {
        return new IdentityProviderAuthorityRecoveryContext(
                "admin",
                "req-123",
                "203.0.113.9",
                "SkillHub Browser");
    }
}
