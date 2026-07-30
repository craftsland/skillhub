package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.entity.IdentityBinding;
import com.iflytek.skillhub.auth.entity.IdentityBindingStatus;
import com.iflytek.skillhub.auth.entity.IdentityBindingSubject;
import com.iflytek.skillhub.auth.entity.IdentityBindingSubjectStatus;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.auth.repository.IdentityBindingSubjectRepository;
import com.iflytek.skillhub.auth.policy.AccessDecision;
import com.iflytek.skillhub.auth.policy.AccessPolicy;
import com.iflytek.skillhub.auth.policy.IdentityAccessContext;
import com.iflytek.skillhub.auth.policy.IdentityAccessKind;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.namespace.GlobalNamespaceMembershipService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

class IdentityResolutionTransactionTest {

    private static final Instant AUTHENTICATED_AT =
            Instant.parse("2026-07-30T08:00:00Z");

    private IdentityBindingRepository bindingRepository;
    private IdentityBindingSubjectRepository subjectRepository;
    private UserAccountRepository userRepository;
    private GlobalNamespaceMembershipService membershipService;
    private AccountLoginGuard accountLoginGuard;
    private PlatformPrincipalFactory principalFactory;
    private AccessPolicy accessPolicy;
    private ProvisioningPolicy provisioningPolicy;
    private ProfileSynchronizationService profileSyncService;
    private AuditLogService auditLogService;
    private IdentityResolutionTransaction transaction;

    @BeforeEach
    void setUp() {
        bindingRepository = mock(IdentityBindingRepository.class);
        subjectRepository =
                mock(IdentityBindingSubjectRepository.class);
        userRepository = mock(UserAccountRepository.class);
        membershipService =
                mock(GlobalNamespaceMembershipService.class);
        accountLoginGuard = new AccountLoginGuard();
        principalFactory = mock(PlatformPrincipalFactory.class);
        accessPolicy = mock(AccessPolicy.class);
        provisioningPolicy = mock(ProvisioningPolicy.class);
        profileSyncService =
                mock(ProfileSynchronizationService.class);
        auditLogService = mock(AuditLogService.class);
        transaction = new IdentityResolutionTransaction(
                bindingRepository,
                subjectRepository,
                userRepository,
                membershipService,
                accountLoginGuard,
                principalFactory,
                accessPolicy,
                provisioningPolicy,
                profileSyncService,
                auditLogService);
        when(subjectRepository.findMatchingSubjects(any(), any()))
                .thenReturn(List.of());
        when(bindingRepository.findByProviderCodeAndSubject(
                any(),
                any())).thenReturn(Optional.empty());
        when(userRepository.save(any(UserAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(accessPolicy.evaluate(any()))
                .thenReturn(AccessDecision.ALLOW);
        when(provisioningPolicy.evaluate(any()))
                .thenAnswer(invocation -> invocation
                        .<ProvisioningPolicyContext>getArgument(0)
                        .configuredMode());
        when(bindingRepository.save(any(IdentityBinding.class)))
                .thenAnswer(invocation -> {
                    IdentityBinding binding =
                            invocation.getArgument(0);
                    if (binding.getId() == null) {
                        ReflectionTestUtils.setField(
                                binding,
                                "id",
                                100L);
                    }
                    return binding;
                });
    }

    @Test
    void createsAccountAndDualWritesLegacyAndTypedSubjects() {
        IdentityAssertion assertion = assertion(
                new ExternalSubject("stable_id", "stable-123"),
                Set.of(
                        new ExternalSubject(
                                "legacy_id",
                                "legacy-123"),
                        new ExternalSubject(
                                "alias_id",
                                "alias-123")));
        PlatformPrincipal principal = principal("generated");
        when(principalFactory.create(
                any(UserAccount.class),
                org.mockito.ArgumentMatchers.eq("provider")))
                .thenReturn(principal);

        IdentityLoginOutcome outcome = transaction.resolve(
                assertion,
                descriptor(
                        "provider",
                        "stable_id",
                        "legacy_id",
                        ProvisioningMode.AUTO),
                IdentityLoginContext.empty());

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.Authenticated(
                        principal,
                        true,
                        true));
        ArgumentCaptor<IdentityBinding> bindingCaptor =
                ArgumentCaptor.forClass(IdentityBinding.class);
        verify(bindingRepository, org.mockito.Mockito.atLeastOnce())
                .save(bindingCaptor.capture());
        IdentityBinding binding =
                bindingCaptor.getAllValues().getFirst();
        assertThat(binding.getSubject()).isEqualTo("legacy-123");
        assertThat(binding.getStatus())
                .isEqualTo(IdentityBindingStatus.ACTIVE);
        assertThat(binding.getLastAuthenticatedAt())
                .isEqualTo(AUTHENTICATED_AT);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<IdentityBindingSubject>> subjectsCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(subjectRepository).saveAll(
                subjectsCaptor.capture());
        assertThat(subjectsCaptor.getValue())
                .extracting(
                        IdentityBindingSubject::getSubjectType,
                        IdentityBindingSubject::getSubjectValue,
                        IdentityBindingSubject::isPrimary)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple(
                                "stable_id",
                                "stable-123",
                                true),
                        org.assertj.core.groups.Tuple.tuple(
                                "legacy_id",
                                "legacy-123",
                                false),
                        org.assertj.core.groups.Tuple.tuple(
                                "alias_id",
                                "alias-123",
                                false));
        verify(membershipService).ensureMember(any());
    }

    @Test
    void approvalProvisioningCreatesOnePendingAccountWithoutMembership() {
        IdentityLoginOutcome outcome = transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.APPROVAL),
                IdentityLoginContext.empty());

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.PendingApproval(
                        "ACCOUNT_PENDING"));
        ArgumentCaptor<UserAccount> userCaptor =
                ArgumentCaptor.forClass(UserAccount.class);
        verify(userRepository, org.mockito.Mockito.atLeastOnce())
                .save(userCaptor.capture());
        assertThat(userCaptor.getValue().getStatus())
                .isEqualTo(UserStatus.PENDING);
        verify(membershipService, never()).ensureMember(any());
        verify(profileSyncService).synchronize(
                any(UserAccount.class),
                any(IdentityAssertion.class),
                any(ProviderDescriptor.class),
                org.mockito.ArgumentMatchers.eq(true));
    }

    @Test
    void existingBindingOnlyRejectsUnknownIdentityWithoutWriting() {
        assertThatThrownBy(() -> transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(
                        ProvisioningMode.EXISTING_BINDING_ONLY),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.ACCESS_DENIED);

        verify(userRepository, never()).save(any());
        verify(bindingRepository, never())
                .save(any(IdentityBinding.class));
        verify(profileSyncService, never()).synchronize(
                any(),
                any(),
                any(),
                org.mockito.ArgumentMatchers.anyBoolean());
    }

    @Test
    void verifiedEmailCollisionReturnsOnlyStableLinkReason() {
        when(userRepository.existsByEmailIgnoreCase(
                "alice@example.com"))
                .thenReturn(true);

        IdentityLoginOutcome outcome = transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.AUTO),
                new IdentityLoginContext(
                        "request-1",
                        "127.0.0.1",
                        "test"));

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.LinkRequired(
                        "EMAIL_COLLISION"));
        verify(userRepository, never()).save(any());
        verify(bindingRepository, never())
                .save(any(IdentityBinding.class));
        verify(auditLogService).record(
                org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.eq(
                        "IDENTITY_EMAIL_COLLISION"),
                org.mockito.ArgumentMatchers.eq(
                        "IDENTITY_BINDING"),
                org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.eq("request-1"),
                org.mockito.ArgumentMatchers.eq("127.0.0.1"),
                org.mockito.ArgumentMatchers.eq("test"),
                org.mockito.ArgumentMatchers.eq(
                        "{\"providerCode\":\"github\",\"result\":\"link_required\"}"));
    }

    @Test
    void loginPolicyReceivesNewIdentityContextBeforeProvisioning() {
        when(principalFactory.create(
                any(UserAccount.class),
                org.mockito.ArgumentMatchers.eq("github")))
                .thenReturn(principal("provisioned"));

        transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.AUTO),
                IdentityLoginContext.empty());

        ArgumentCaptor<IdentityAccessContext> context =
                ArgumentCaptor.forClass(
                        IdentityAccessContext.class);
        verify(accessPolicy).evaluate(context.capture());
        assertThat(context.getValue().accessKind())
                .isEqualTo(IdentityAccessKind.NEW_IDENTITY);
        assertThat(context.getValue().existingAccountStatus())
                .isEmpty();
    }

    @Test
    void deniedLoginPolicyDoesNotProvisionUnknownIdentity() {
        when(accessPolicy.evaluate(any()))
                .thenReturn(AccessDecision.DENY);

        assertThatThrownBy(() -> transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.AUTO),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.ACCESS_DENIED);

        verify(provisioningPolicy, never()).evaluate(any());
        verify(userRepository, never()).save(any());
        verify(bindingRepository, never())
                .save(any(IdentityBinding.class));
    }

    @Test
    void upgradesLegacyPrimaryInOneTransaction() {
        IdentityBinding binding = binding(
                1L,
                "usr_1",
                "github",
                "123456");
        IdentityBindingSubject legacy =
                subject(
                        1L,
                        "github",
                        "legacy_subject",
                        "123456",
                        true);
        UserAccount user = user("usr_1", UserStatus.ACTIVE, false);
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.of(binding));
        when(bindingRepository.findByIdAndStatusForUpdate(
                1L,
                IdentityBindingStatus.ACTIVE))
                .thenReturn(Optional.of(binding));
        when(subjectRepository.findByBindingIdAndStatusForUpdate(
                1L,
                IdentityBindingSubjectStatus.ACTIVE))
                .thenReturn(List.of(legacy));
        when(userRepository.findByIdForUpdate("usr_1"))
                .thenReturn(Optional.of(user));
        when(principalFactory.create(user, "github"))
                .thenReturn(principal("usr_1"));

        transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.AUTO),
                IdentityLoginContext.empty());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<IdentityBindingSubject>> subjectsCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(subjectRepository).saveAll(
                subjectsCaptor.capture());
        assertThat(subjectsCaptor.getValue())
                .extracting(
                        IdentityBindingSubject::getSubjectType,
                        IdentityBindingSubject::getSubjectValue,
                        IdentityBindingSubject::isPrimary)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple(
                                "legacy_subject",
                                "123456",
                                false),
                        org.assertj.core.groups.Tuple.tuple(
                                "github_user_id",
                                "123456",
                                true));
        ArgumentCaptor<IdentityAccessContext> accessContext =
                ArgumentCaptor.forClass(
                        IdentityAccessContext.class);
        verify(accessPolicy).evaluate(accessContext.capture());
        assertThat(accessContext.getValue().accessKind())
                .isEqualTo(
                        IdentityAccessKind.RETURNING_IDENTITY);
        assertThat(accessContext.getValue()
                .existingAccountStatus())
                .contains(UserStatus.ACTIVE);
    }

    @Test
    void resolvesMultipleAliasesOnlyWhenTheyBelongToOneBinding() {
        IdentityAssertion assertion = assertion(
                new ExternalSubject("stable_id", "stable-123"),
                Set.of(
                        new ExternalSubject(
                                "legacy_id",
                                "legacy-123"),
                        new ExternalSubject(
                                "alias_id",
                                "alias-123")));
        IdentityBinding binding = binding(
                1L,
                "usr_1",
                "provider",
                "legacy-123");
        IdentityBindingSubject alias =
                subject(
                        1L,
                        "provider",
                        "alias_id",
                        "alias-123",
                        true);
        IdentityBindingSubject stable =
                subject(
                        1L,
                        "provider",
                        "stable_id",
                        "stable-123",
                        false);
        when(subjectRepository.findMatchingSubjects(
                org.mockito.ArgumentMatchers.eq("provider"),
                any())).thenReturn(List.of(alias, stable));
        when(bindingRepository.findByProviderCodeAndSubject(
                "provider",
                "legacy-123")).thenReturn(Optional.of(binding));
        when(bindingRepository.findByIdAndStatusForUpdate(
                1L,
                IdentityBindingStatus.ACTIVE))
                .thenReturn(Optional.of(binding));
        when(subjectRepository.findByBindingIdAndStatusForUpdate(
                1L,
                IdentityBindingSubjectStatus.ACTIVE))
                .thenReturn(List.of(alias, stable));
        UserAccount user = user("usr_1", UserStatus.ACTIVE, false);
        when(userRepository.findByIdForUpdate("usr_1"))
                .thenReturn(Optional.of(user));
        when(principalFactory.create(user, "provider"))
                .thenReturn(principal("usr_1"));

        transaction.resolve(
                assertion,
                descriptor(
                        "provider",
                        "stable_id",
                        "legacy_id",
                        ProvisioningMode.AUTO),
                IdentityLoginContext.empty());

        assertThat(alias.isPrimary()).isFalse();
        assertThat(stable.isPrimary()).isTrue();
    }

    @Test
    void aliasesResolvingToDifferentBindingsFailClosed() {
        IdentityAssertion assertion = assertion(
                new ExternalSubject("stable_id", "stable-123"),
                Set.of(
                        new ExternalSubject(
                                "legacy_id",
                                "legacy-123"),
                        new ExternalSubject(
                                "alias_id",
                                "alias-123")));
        when(subjectRepository.findMatchingSubjects(
                org.mockito.ArgumentMatchers.eq("provider"),
                any())).thenReturn(List.of(
                        subject(
                                1L,
                                "provider",
                                "stable_id",
                                "stable-123",
                                true),
                        subject(
                                2L,
                                "provider",
                                "alias_id",
                                "alias-123",
                                true)));

        assertThatThrownBy(() -> transaction.resolve(
                assertion,
                descriptor(
                        "provider",
                        "stable_id",
                        "legacy_id",
                        ProvisioningMode.AUTO),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(
                        IdentityFailureCode
                                .IDENTITY_IDENTIFIER_CONFLICT);
        verify(userRepository, never()).save(any());
    }

    @Test
    void revokedPrimaryCannotBeAutomaticallyReactivated() {
        IdentityBindingSubject revoked =
                subject(
                        1L,
                        "github",
                        "github_user_id",
                        "123456",
                        false);
        ReflectionTestUtils.setField(
                revoked,
                "status",
                IdentityBindingSubjectStatus.REVOKED);
        ReflectionTestUtils.setField(
                revoked,
                "revokedAt",
                AUTHENTICATED_AT.minusSeconds(60));
        when(subjectRepository.findMatchingSubjects(
                org.mockito.ArgumentMatchers.eq("github"),
                any())).thenReturn(List.of(revoked));

        assertThatThrownBy(() -> transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.AUTO),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.ACCESS_DENIED);
        verify(bindingRepository, never())
                .findByIdAndStatusForUpdate(any(), any());
    }

    @Test
    void pendingAccountUpgradesSubjectsWithoutMutatingProfile() {
        IdentityBinding binding = binding(
                1L,
                "usr_1",
                "github",
                "123456");
        UserAccount user = user("usr_1", UserStatus.PENDING, false);
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.of(binding));
        when(bindingRepository.findByIdAndStatusForUpdate(
                1L,
                IdentityBindingStatus.ACTIVE))
                .thenReturn(Optional.of(binding));
        when(subjectRepository.findByBindingIdAndStatusForUpdate(
                1L,
                IdentityBindingSubjectStatus.ACTIVE))
                .thenReturn(List.of());
        when(userRepository.findByIdForUpdate("usr_1"))
                .thenReturn(Optional.of(user));

        IdentityLoginOutcome outcome = transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.AUTO),
                IdentityLoginContext.empty());

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.PendingApproval(
                        "ACCOUNT_PENDING"));
        assertThat(user.getDisplayName()).isEqualTo("original");
        assertThat(user.getEmail())
                .isEqualTo("original@example.com");
        verify(userRepository, never()).save(user);
        verify(subjectRepository).saveAll(any());
        ArgumentCaptor<IdentityAccessContext> accessContext =
                ArgumentCaptor.forClass(
                        IdentityAccessContext.class);
        verify(accessPolicy).evaluate(accessContext.capture());
        assertThat(accessContext.getValue().accessKind())
                .isEqualTo(
                        IdentityAccessKind.RETURNING_IDENTITY);
        assertThat(accessContext.getValue()
                .existingAccountStatus())
                .contains(UserStatus.PENDING);
    }

    @Test
    void deniedLoginPolicyDoesNotMutatePendingBinding() {
        IdentityBinding binding = binding(
                1L,
                "usr_1",
                "github",
                "123456");
        UserAccount user = user("usr_1", UserStatus.PENDING, false);
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.of(binding));
        when(bindingRepository.findByIdAndStatusForUpdate(
                1L,
                IdentityBindingStatus.ACTIVE))
                .thenReturn(Optional.of(binding));
        when(userRepository.findByIdForUpdate("usr_1"))
                .thenReturn(Optional.of(user));
        when(accessPolicy.evaluate(any()))
                .thenReturn(AccessDecision.DENY);

        assertThatThrownBy(() -> transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.APPROVAL),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.ACCESS_DENIED);

        verify(subjectRepository, never())
                .demoteActivePrimary(any(), any());
        verify(bindingRepository, never()).save(any());
        verify(auditLogService, never()).record(
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any());
    }

    @Test
    void blockedAccountFailsBeforeAnyBindingMutation() {
        assertBlocked(
                UserStatus.DISABLED,
                false,
                IdentityFailureCode.ACCOUNT_DISABLED);
        assertBlocked(
                UserStatus.MERGED,
                false,
                IdentityFailureCode.ACCOUNT_MERGED);
        assertBlocked(
                UserStatus.ACTIVE,
                true,
                IdentityFailureCode.SYSTEM_ACCOUNT_FORBIDDEN);
    }

    private void assertBlocked(
            UserStatus status,
            boolean system,
            IdentityFailureCode expectedCode) {
        IdentityBinding binding = binding(
                1L,
                "usr_blocked",
                "github",
                "123456");
        UserAccount user = user("usr_blocked", status, system);
        when(bindingRepository.findByProviderCodeAndSubject(
                "github",
                "123456")).thenReturn(Optional.of(binding));
        when(bindingRepository.findByIdAndStatusForUpdate(
                1L,
                IdentityBindingStatus.ACTIVE))
                .thenReturn(Optional.of(binding));
        when(userRepository.findByIdForUpdate("usr_blocked"))
                .thenReturn(Optional.of(user));

        assertThatThrownBy(() -> transaction.resolve(
                githubAssertion(Set.of()),
                githubDescriptor(ProvisioningMode.AUTO),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(expectedCode);
        verify(subjectRepository, never())
                .findByBindingIdAndStatusForUpdate(
                        any(),
                        any());
    }

    private static IdentityAssertion githubAssertion(
            Set<ExternalSubject> aliases) {
        return new IdentityAssertion(
                new ProviderReference(
                        "github",
                        "oauth2-github",
                        "https://github.com"),
                new ExternalSubject(
                        "github_user_id",
                        "123456"),
                aliases,
                profile(),
                Map.of(),
                evidence("oauth2-github"));
    }

    private static IdentityAssertion assertion(
            ExternalSubject primary,
            Set<ExternalSubject> aliases) {
        return new IdentityAssertion(
                new ProviderReference(
                        "provider",
                        "oidc",
                        "https://id.example.com"),
                primary,
                aliases,
                profile(),
                Map.of(),
                evidence("oidc"));
    }

    private static ProviderDescriptor githubDescriptor(
            ProvisioningMode mode) {
        return descriptor(
                "github",
                "github_user_id",
                "github_user_id",
                mode);
    }

    private static ProviderDescriptor descriptor(
            String providerCode,
            String primaryType,
            String legacyType,
            ProvisioningMode mode) {
        Map<String, SubjectCanonicalizer> canonicalizers =
                new java.util.LinkedHashMap<>();
        canonicalizers.put(primaryType, SubjectCanonicalizer.EXACT);
        canonicalizers.put(legacyType, SubjectCanonicalizer.EXACT);
        return new ProviderDescriptor(
                providerCode,
                "oidc",
                "https://id.example.com",
                providerCode,
                primaryType,
                legacyType,
                canonicalizers,
                List.of("login"),
                List.of("email"),
                List.of("avatar_url"),
                EmailAssurance.VERIFIED,
                mode,
                ProfileSyncPolicy.defaults());
    }

    private static ExternalProfile profile() {
        return new ExternalProfile(
                "alice",
                Optional.of(new EmailClaim(
                        "alice@example.com",
                        EmailAssurance.VERIFIED)),
                Optional.of(URI.create(
                        "https://avatars.example/alice.png")));
    }

    private static AuthenticationEvidence evidence(
            String protocol) {
        return new AuthenticationEvidence(
                protocol,
                AUTHENTICATED_AT,
                Set.of("oauth2_authorization_code"));
    }

    private static IdentityBinding binding(
            long id,
            String userId,
            String providerCode,
            String subject) {
        IdentityBinding binding = new IdentityBinding(
                userId,
                providerCode,
                subject,
                "alice");
        ReflectionTestUtils.setField(binding, "id", id);
        return binding;
    }

    private static IdentityBindingSubject subject(
            long bindingId,
            String providerCode,
            String type,
            String value,
            boolean primary) {
        return new IdentityBindingSubject(
                bindingId,
                providerCode,
                type,
                value,
                primary,
                AUTHENTICATED_AT);
    }

    private static UserAccount user(
            String userId,
            UserStatus status,
            boolean system) {
        UserAccount user = system
                ? UserAccount.systemAccount(
                        userId,
                        "original",
                        "original@example.com",
                        null)
                : new UserAccount(
                        userId,
                        "original",
                        "original@example.com",
                        null);
        user.setStatus(status);
        return user;
    }

    private static PlatformPrincipal principal(String userId) {
        return new PlatformPrincipal(
                userId,
                "alice",
                "alice@example.com",
                null,
                "provider",
                Set.of("USER"));
    }
}
