package com.iflytek.skillhub.auth.merge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.AccountLoginGuard;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Pageable;

class AccountMergeIntentTransactionTest {

    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-07-31T09:00:00Z"),
            ZoneOffset.UTC);
    private static final UUID INTENT_ID = UUID.fromString(
            "7e67f099-8d10-4ec3-a24a-e170726f62b8");

    private AccountMergeIntentRepository intentRepository;
    private UserAccountRepository userRepository;
    private AccountMergeDataGateway dataGateway;
    private AuditLogService auditLogService;
    private AccountMergeIntentTransaction transaction;
    private AccountMergeActor actor;

    @BeforeEach
    void setUp() {
        intentRepository =
                mock(AccountMergeIntentRepository.class);
        userRepository = mock(UserAccountRepository.class);
        dataGateway = mock(AccountMergeDataGateway.class);
        auditLogService = mock(AuditLogService.class);
        transaction = new AccountMergeIntentTransaction(
                intentRepository,
                userRepository,
                new AccountLoginGuard(),
                new AccountMergeStateHasher(),
                dataGateway,
                auditLogService,
                CLOCK);
        actor = new AccountMergeActor(
                "usr_primary",
                "local",
                "high-entropy-session-nonce",
                "local-password",
                Instant.parse("2026-07-31T08:59:00Z"),
                new IdentityLoginContext(
                        "req-merge-1",
                        "203.0.113.10",
                        "Browser"));
        when(userRepository.findByIdForUpdate(
                "usr_primary")).thenReturn(Optional.of(
                        new UserAccount(
                                "usr_primary",
                                "Primary",
                                "primary@example.com",
                                null)));
        when(intentRepository.saveAndFlush(any()))
                .thenAnswer(invocation ->
                        invocation.getArgument(0));
    }

    @Test
    void createsIntentWithoutAcceptingASecondaryIdentifier() {
        AccountMergeIntent intent =
                transaction.createIntent(actor, INTENT_ID);

        assertThat(intent.id()).isEqualTo(INTENT_ID);
        assertThat(intent.status()).isEqualTo(
                AccountMergeIntentStatus
                        .PENDING_SECONDARY_PROOF);
        assertThat(intent.expiresAt()).isEqualTo(
                Instant.parse("2026-07-31T09:09:00Z"));
        verify(intentRepository).saveAndFlush(any(
                AccountMergeIntentEntity.class));
        verify(auditLogService).record(
                "usr_primary",
                "ACCOUNT_MERGE_PRIMARY_REAUTHENTICATED",
                "ACCOUNT_MERGE_INTENT",
                null,
                "req-merge-1",
                "203.0.113.10",
                "Browser",
                "{\"intentId\":\""
                        + INTENT_ID
                        + "\",\"result\":\"local-password\"}");
        verify(auditLogService).record(
                "usr_primary",
                "ACCOUNT_MERGE_INTENT_CREATED",
                "ACCOUNT_MERGE_INTENT",
                null,
                "req-merge-1",
                "203.0.113.10",
                "Browser",
                "{\"intentId\":\""
                        + INTENT_ID
                        + "\",\"result\":"
                        + "\"pending_secondary_proof\"}");
    }

    @Test
    void rejectsAnIneligiblePrimaryAccount() {
        UserAccount systemAccount = UserAccount.systemAccount(
                "usr_primary",
                "System",
                null,
                null);
        when(userRepository.findByIdForUpdate(
                "usr_primary")).thenReturn(
                        Optional.of(systemAccount));

        assertThatThrownBy(() ->
                transaction.createIntent(actor, INTENT_ID))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_ACCOUNT_NOT_ELIGIBLE));
    }

    @Test
    void recordsSecondaryProofOnlyAfterIndependentAuthentication() {
        AccountMergeIntentEntity intent =
                new AccountMergeIntentEntity(
                        INTENT_ID,
                        "usr_primary",
                        new AccountMergeStateHasher().hash(
                                "high-entropy-session-nonce"),
                        "local-password",
                        Instant.parse(
                                "2026-07-31T08:59:00Z"),
                        Instant.parse(
                                "2026-07-31T09:10:00Z"),
                        Instant.parse(
                                "2026-07-31T09:00:00Z"));
        when(intentRepository.findByIdForUpdate(INTENT_ID))
                .thenReturn(Optional.of(intent));
        when(userRepository.findByIdForUpdate(
                "usr_secondary")).thenReturn(Optional.of(
                        new UserAccount(
                                "usr_secondary",
                                "Secondary",
                                "secondary@example.com",
                                null)));
        when(intentRepository
                .findActiveByParticipantForUpdate(
                        "usr_secondary",
                        AccountMergeIntentTransactionTest
                                .activeStatuses()))
                .thenReturn(List.of());

        AccountMergeIntent result =
                transaction.recordSecondaryProof(
                        actor,
                        INTENT_ID,
                        "usr_secondary",
                        "local-password");

        assertThat(result.status()).isEqualTo(
                AccountMergeIntentStatus.READY_FOR_PREVIEW);
        assertThat(intent.getSecondaryUserId())
                .isEqualTo("usr_secondary");
    }

    @Test
    void backgroundCleanupExpiresAndAuditsDueIntents() {
        AccountMergeIntentEntity expired =
                new AccountMergeIntentEntity(
                        INTENT_ID,
                        "usr_primary",
                        new AccountMergeStateHasher().hash(
                                "high-entropy-session-nonce"),
                        "local-password",
                        Instant.parse(
                                "2026-07-31T08:49:00Z"),
                        Instant.parse(
                                "2026-07-31T08:59:00Z"),
                        Instant.parse(
                                "2026-07-31T08:49:00Z"));
        when(intentRepository.findExpiredForUpdate(
                any(),
                any(),
                any(Pageable.class)))
                .thenReturn(List.of(expired));

        assertThat(transaction.expireDueIntents(100))
                .isEqualTo(1);
        assertThat(expired.getStatus()).isEqualTo(
                AccountMergeIntentStatus.EXPIRED);
        verify(auditLogService).record(
                "usr_primary",
                "ACCOUNT_MERGE_EXPIRED",
                "ACCOUNT_MERGE_INTENT",
                null,
                null,
                null,
                null,
                "{\"intentId\":\""
                        + INTENT_ID
                        + "\",\"result\":\"expired\"}");
        verify(intentRepository).flush();
    }

    private static java.util.Set<AccountMergeIntentStatus>
            activeStatuses() {
        return java.util.Set.of(
                AccountMergeIntentStatus
                        .PENDING_SECONDARY_PROOF,
                AccountMergeIntentStatus
                        .READY_FOR_PREVIEW,
                AccountMergeIntentStatus
                        .READY_TO_CONFIRM,
                AccountMergeIntentStatus
                        .FAILED_CONFLICT);
    }
}
