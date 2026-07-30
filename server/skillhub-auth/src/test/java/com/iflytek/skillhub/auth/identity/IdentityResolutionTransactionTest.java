package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.entity.IdentityBinding;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.domain.namespace.GlobalNamespaceMembershipService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class IdentityResolutionTransactionTest {

    private IdentityBindingRepository bindingRepository;
    private UserAccountRepository userRepository;
    private GlobalNamespaceMembershipService membershipService;
    private AccountLoginGuard accountLoginGuard;
    private PlatformPrincipalFactory principalFactory;
    private IdentityResolutionTransaction transaction;

    @BeforeEach
    void setUp() {
        bindingRepository = mock(IdentityBindingRepository.class);
        userRepository = mock(UserAccountRepository.class);
        membershipService = mock(GlobalNamespaceMembershipService.class);
        accountLoginGuard = new AccountLoginGuard();
        principalFactory = mock(PlatformPrincipalFactory.class);
        transaction = new IdentityResolutionTransaction(
                bindingRepository,
                userRepository,
                membershipService,
                accountLoginGuard,
                principalFactory);
    }

    @Test
    void createsActiveAccountBindingMembershipAndPrincipal() {
        IdentityAssertion assertion = assertion(
                EmailAssurance.VERIFIED,
                "alice@example.com");
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.empty());
        when(userRepository.save(any(UserAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        PlatformPrincipal principal = principal("generated");
        when(principalFactory.create(any(UserAccount.class), org.mockito.ArgumentMatchers.eq("github")))
                .thenReturn(principal);

        IdentityLoginOutcome outcome =
                transaction.resolve(assertion, UserStatus.ACTIVE);

        assertThat(outcome)
                .isEqualTo(new IdentityLoginOutcome.Authenticated(
                        principal,
                        true,
                        true));
        ArgumentCaptor<UserAccount> userCaptor =
                ArgumentCaptor.forClass(UserAccount.class);
        verify(userRepository).save(userCaptor.capture());
        UserAccount created = userCaptor.getValue();
        assertThat(created.getId()).startsWith("usr_");
        assertThat(created.getDisplayName()).isEqualTo("alice");
        assertThat(created.getEmail()).isEqualTo("alice@example.com");
        assertThat(created.getAvatarUrl())
                .isEqualTo("https://avatars.example/alice.png");
        verify(membershipService).ensureMember(created.getId());
        ArgumentCaptor<IdentityBinding> bindingCaptor =
                ArgumentCaptor.forClass(IdentityBinding.class);
        verify(bindingRepository).save(bindingCaptor.capture());
        assertThat(bindingCaptor.getValue().getProviderCode())
                .isEqualTo("github");
        assertThat(bindingCaptor.getValue().getSubject())
                .isEqualTo("123456");
    }

    @Test
    void createsPendingAccountWithoutMembershipOrSessionPrincipal() {
        IdentityAssertion assertion = assertion(
                EmailAssurance.VERIFIED,
                "alice@example.com");
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.empty());
        when(userRepository.save(any(UserAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        IdentityLoginOutcome outcome =
                transaction.resolve(assertion, UserStatus.PENDING);

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.PendingApproval("ACCOUNT_PENDING"));
        verify(membershipService, never()).ensureMember(any());
        verify(principalFactory, never()).create(any(), any());
        verify(bindingRepository).save(any(IdentityBinding.class));
    }

    @Test
    void existingApprovedAccountIgnoresPendingProvisioningDefault() {
        IdentityBinding binding =
                new IdentityBinding("usr_1", "github", "123456", "alice");
        UserAccount user = new UserAccount(
                "usr_1",
                "old",
                "old@example.com",
                null);
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.of(binding));
        when(userRepository.findById("usr_1")).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);
        PlatformPrincipal principal = principal("usr_1");
        when(principalFactory.create(user, "github")).thenReturn(principal);

        IdentityLoginOutcome outcome =
                transaction.resolve(
                        assertion(EmailAssurance.VERIFIED, "alice@example.com"),
                        UserStatus.PENDING);

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.Authenticated(
                        principal,
                        false,
                        false));
        assertThat(user.getDisplayName()).isEqualTo("alice");
        assertThat(user.getEmail()).isEqualTo("alice@example.com");
        verify(membershipService, never()).ensureMember(any());
        verify(bindingRepository, never()).save(binding);
    }

    @Test
    void existingPendingAccountReturnsPendingBeforeProfileMutation() {
        IdentityBinding binding =
                new IdentityBinding("usr_1", "github", "123456", "alice");
        UserAccount user = new UserAccount(
                "usr_1",
                "original",
                "original@example.com",
                null);
        user.setStatus(UserStatus.PENDING);
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.of(binding));
        when(userRepository.findById("usr_1")).thenReturn(Optional.of(user));

        IdentityLoginOutcome outcome =
                transaction.resolve(
                        assertion(EmailAssurance.VERIFIED, "changed@example.com"),
                        UserStatus.ACTIVE);

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.PendingApproval("ACCOUNT_PENDING"));
        assertThat(user.getDisplayName()).isEqualTo("original");
        assertThat(user.getEmail()).isEqualTo("original@example.com");
        verify(userRepository, never()).save(user);
        verify(principalFactory, never()).create(any(), any());
    }

    @Test
    void blockedExistingAccountFailsBeforeProfileMutation() {
        assertBlocked(UserStatus.DISABLED, false, IdentityFailureCode.ACCOUNT_DISABLED);
        assertBlocked(UserStatus.MERGED, false, IdentityFailureCode.ACCOUNT_MERGED);
        assertBlocked(UserStatus.ACTIVE, true, IdentityFailureCode.SYSTEM_ACCOUNT_FORBIDDEN);
    }

    @Test
    void unverifiedEmailNeverPopulatesOrOverwritesTrustedProfile() {
        IdentityAssertion assertion = assertion(
                EmailAssurance.UNVERIFIED,
                "unverified@example.com");
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.empty());
        when(userRepository.save(any(UserAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(principalFactory.create(any(), any())).thenReturn(principal("new"));

        transaction.resolve(assertion, UserStatus.ACTIVE);

        ArgumentCaptor<UserAccount> userCaptor =
                ArgumentCaptor.forClass(UserAccount.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getEmail()).isNull();
    }

    private void assertBlocked(
            UserStatus status,
            boolean system,
            IdentityFailureCode expectedCode) {
        IdentityBindingRepository localBindingRepository =
                mock(IdentityBindingRepository.class);
        UserAccountRepository localUserRepository =
                mock(UserAccountRepository.class);
        IdentityResolutionTransaction localTransaction =
                new IdentityResolutionTransaction(
                        localBindingRepository,
                        localUserRepository,
                        membershipService,
                        accountLoginGuard,
                        principalFactory);
        IdentityBinding binding =
                new IdentityBinding("usr_blocked", "github", "123456", "old");
        UserAccount user = system
                ? UserAccount.systemAccount(
                        "usr_blocked",
                        "original",
                        "original@example.com",
                        null)
                : new UserAccount(
                        "usr_blocked",
                        "original",
                        "original@example.com",
                        null);
        user.setStatus(status);
        when(localBindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.of(binding));
        when(localUserRepository.findById("usr_blocked"))
                .thenReturn(Optional.of(user));

        assertThatThrownBy(() -> localTransaction.resolve(
                assertion(EmailAssurance.VERIFIED, "changed@example.com"),
                UserStatus.ACTIVE))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(expectedCode);

        assertThat(user.getDisplayName()).isEqualTo("original");
        assertThat(user.getEmail()).isEqualTo("original@example.com");
        verify(localUserRepository, never()).save(user);
    }

    private static IdentityAssertion assertion(
            EmailAssurance assurance,
            String email) {
        return new IdentityAssertion(
                new ProviderReference(
                        "github",
                        "oauth2-github",
                        "https://github.com"),
                new ExternalSubject("github_user_id", "123456"),
                Set.of(),
                new ExternalProfile(
                        "alice",
                        Optional.of(new EmailClaim(email, assurance)),
                        Optional.of(URI.create(
                                "https://avatars.example/alice.png"))),
                Map.of(),
                new AuthenticationEvidence(
                        "oauth2-github",
                        Instant.parse("2026-07-30T08:00:00Z"),
                        Set.of("oauth2_authorization_code")));
    }

    private static PlatformPrincipal principal(String userId) {
        return new PlatformPrincipal(
                userId,
                "alice",
                "alice@example.com",
                null,
                "github",
                Set.of("USER"));
    }
}
