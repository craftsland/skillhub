package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.entity.IdentityBindingStatus;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequest;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import com.iflytek.skillhub.auth.local.LocalCredentialRepository;
import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.auth.repository.IdentityBindingSubjectRepository;
import com.iflytek.skillhub.auth.repository.IdentityLinkRequestRepository;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class IdentityLinkTransactionCasCapabilityTest {

    private final IdentityLinkRequestRepository requestRepository =
            mock(IdentityLinkRequestRepository.class);
    private final IdentityBindingRepository bindingRepository =
            mock(IdentityBindingRepository.class);
    private final IdentityBindingSubjectRepository subjectRepository =
            mock(IdentityBindingSubjectRepository.class);
    private final LocalCredentialRepository credentialRepository =
            mock(LocalCredentialRepository.class);
    private final UserAccountRepository userRepository =
            mock(UserAccountRepository.class);
    private final IdentityProviderRegistry providerRegistry =
            mock(IdentityProviderRegistry.class);
    private final IdentityLinkStateHasher stateHasher =
            new IdentityLinkStateHasher();
    private final AccountLoginGuard accountLoginGuard =
            mock(AccountLoginGuard.class);
    private final PlatformPrincipalFactory principalFactory =
            mock(PlatformPrincipalFactory.class);
    private final AuditLogService auditLogService =
            mock(AuditLogService.class);
    private final UserAccount user = mock(UserAccount.class);
    private final IdentityLinkTransaction transaction =
            new IdentityLinkTransaction(
                    requestRepository,
                    bindingRepository,
                    subjectRepository,
                    credentialRepository,
                    userRepository,
                    providerRegistry,
                    stateHasher,
                    accountLoginGuard,
                    principalFactory,
                    auditLogService,
                    Clock.fixed(
                            Instant.parse("2026-07-31T08:00:00Z"),
                            ZoneOffset.UTC));

    @BeforeEach
    void configureReadyCasProvider() {
        when(providerRegistry.listReadyLoginMethods())
                .thenReturn(List.of(new IdentityProviderLoginMethod(
                        "cas-main",
                        "Corporate CAS",
                        IdentityProviderLoginMethodType.CAS_REDIRECT)));
        when(accountLoginGuard.evaluateInteractive(user))
                .thenReturn(AccountLoginDecision.ALLOWED);
    }

    @Test
    void exposesReadyCasAsAnAvailableIdentityLinkProvider() {
        when(userRepository.findById("usr_1"))
                .thenReturn(Optional.of(user));
        when(bindingRepository.findByUserIdAndStatus(
                "usr_1",
                IdentityBindingStatus.ACTIVE))
                .thenReturn(List.of());
        when(credentialRepository.existsByUserId("usr_1"))
                .thenReturn(true);

        IdentityLinkAccountState state =
                transaction.accountState("usr_1");

        assertThat(state.availableProviders())
                .containsExactly(new IdentityLinkProviderView(
                        "cas-main",
                        "Corporate CAS",
                        Set.of(
                                IdentityProviderLoginMethodType
                                        .CAS_REDIRECT)));
    }

    @Test
    void createsLinkIntentForReadyCasProvider() {
        UUID intentId = UUID.fromString(
                "94a94b82-bdb6-46bf-a1ff-910514519308");
        IdentityLinkActor actor = new IdentityLinkActor(
                "usr_1",
                "local",
                "session-nonce",
                new IdentityLoginContext(
                        "req-1",
                        "127.0.0.1",
                        "JUnit"));
        when(userRepository.findByIdForUpdate("usr_1"))
                .thenReturn(Optional.of(user));
        when(bindingRepository.findByUserIdAndStatus(
                "usr_1",
                IdentityBindingStatus.ACTIVE))
                .thenReturn(List.of());
        when(requestRepository.findActiveByPrimaryUserIdForUpdate(
                any(),
                any())).thenReturn(Optional.empty());
        when(requestRepository.saveAndFlush(
                any(IdentityLinkRequest.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        IdentityLinkIntent intent = transaction.createLinkIntent(
                actor,
                intentId,
                "cas-main");

        assertThat(intent.id()).isEqualTo(intentId);
        assertThat(intent.providerCode()).isEqualTo("cas-main");
        assertThat(intent.status()).isEqualTo(
                IdentityLinkRequestStatus
                        .PENDING_REAUTHENTICATION);
    }
}
