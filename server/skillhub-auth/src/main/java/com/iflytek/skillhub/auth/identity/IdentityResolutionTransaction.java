package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.entity.IdentityBinding;
import com.iflytek.skillhub.auth.entity.IdentityBindingStatus;
import com.iflytek.skillhub.auth.entity.IdentityBindingSubject;
import com.iflytek.skillhub.auth.entity.IdentityBindingSubjectStatus;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short database transaction for Binding V2 resolution, legacy compatibility,
 * and provisioning. Protocol I/O has already completed before this service is
 * invoked.
 */
@Service
class IdentityResolutionTransaction {

    private static final String ACCOUNT_PENDING = "ACCOUNT_PENDING";
    private static final String EMAIL_COLLISION = "EMAIL_COLLISION";
    private static final String LEGACY_SUBJECT_TYPE = "legacy_subject";

    private final IdentityBindingRepository bindingRepository;
    private final IdentityBindingSubjectRepository subjectRepository;
    private final UserAccountRepository userRepository;
    private final GlobalNamespaceMembershipService membershipService;
    private final AccountLoginGuard accountLoginGuard;
    private final PlatformPrincipalFactory principalFactory;
    private final AccessPolicy accessPolicy;
    private final ProvisioningPolicy provisioningPolicy;
    private final ProfileSynchronizationService profileSyncService;
    private final AuditLogService auditLogService;

    IdentityResolutionTransaction(
            IdentityBindingRepository bindingRepository,
            IdentityBindingSubjectRepository subjectRepository,
            UserAccountRepository userRepository,
            GlobalNamespaceMembershipService membershipService,
            AccountLoginGuard accountLoginGuard,
            PlatformPrincipalFactory principalFactory,
            AccessPolicy accessPolicy,
            ProvisioningPolicy provisioningPolicy,
            ProfileSynchronizationService profileSyncService,
            AuditLogService auditLogService) {
        this.bindingRepository = bindingRepository;
        this.subjectRepository = subjectRepository;
        this.userRepository = userRepository;
        this.membershipService = membershipService;
        this.accountLoginGuard = accountLoginGuard;
        this.principalFactory = principalFactory;
        this.accessPolicy = accessPolicy;
        this.provisioningPolicy = provisioningPolicy;
        this.profileSyncService = profileSyncService;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public IdentityLoginOutcome resolve(
            IdentityAssertion assertion,
            ProviderDescriptor descriptor,
            IdentityLoginContext context) {
        ExternalSubject legacySubject =
                assertion.requireUniqueSubject(
                        descriptor.legacyPrimarySubjectType());
        MatchResolution initialMatches =
                resolveMatches(assertion, legacySubject);
        if (initialMatches.bindingId() == null) {
            requireAccessAllowed(
                    assertion,
                    context,
                    IdentityAccessKind.NEW_IDENTITY,
                    Optional.empty());
            ProvisioningMode mode = provisioningPolicy.evaluate(
                    new ProvisioningPolicyContext(
                            assertion.provider(),
                            descriptor.provisioningMode(),
                            context));
            return createAccount(
                    assertion,
                    legacySubject,
                    descriptor,
                    mode,
                    context);
        }

        IdentityBinding binding = bindingRepository
                .findByIdAndStatusForUpdate(
                        initialMatches.bindingId(),
                        IdentityBindingStatus.ACTIVE)
                .orElseThrow(this::identifierConflict);
        MatchResolution lockedMatches =
                resolveMatches(assertion, legacySubject);
        if (!binding.getId().equals(lockedMatches.bindingId())) {
            throw identifierConflict();
        }
        return resolveExisting(
                assertion,
                legacySubject,
                binding,
                lockedMatches.revokedAliases(),
                descriptor,
                context);
    }

    private MatchResolution resolveMatches(
            IdentityAssertion assertion,
            ExternalSubject legacySubject) {
        List<IdentityBindingSubject> typedMatches =
                subjectRepository.findMatchingSubjects(
                        assertion.provider().providerCode(),
                        subjectValuesByType(assertion.allSubjects()));
        IdentityBinding legacyMatch = bindingRepository
                .findByProviderCodeAndSubject(
                        assertion.provider().providerCode(),
                        legacySubject.value())
                .orElse(null);

        LinkedHashSet<Long> activeBindingIds = typedMatches.stream()
                .filter(subject -> subject.getStatus()
                        == IdentityBindingSubjectStatus.ACTIVE)
                .map(IdentityBindingSubject::getBindingId)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (legacyMatch != null) {
            if (legacyMatch.getStatus() == IdentityBindingStatus.ACTIVE) {
                activeBindingIds.add(legacyMatch.getId());
            } else if (activeBindingIds.isEmpty()) {
                throw accessDenied();
            } else {
                throw identifierConflict();
            }
        }
        if (activeBindingIds.size() > 1) {
            throw identifierConflict();
        }

        Map<ExternalSubject, List<IdentityBindingSubject>> matchesBySubject =
                typedMatches.stream().collect(Collectors.groupingBy(
                        this::externalSubject,
                        LinkedHashMap::new,
                        Collectors.toList()));
        if (activeBindingIds.isEmpty()) {
            if (matchesBySubject.values().stream()
                    .flatMap(List::stream)
                    .anyMatch(subject -> subject.getStatus()
                            == IdentityBindingSubjectStatus.REVOKED)) {
                throw accessDenied();
            }
            return new MatchResolution(null, Set.of());
        }

        Long bindingId = activeBindingIds.getFirst();
        LinkedHashSet<ExternalSubject> revokedAliases =
                new LinkedHashSet<>();
        for (ExternalSubject assertedSubject : assertion.allSubjects()) {
            List<IdentityBindingSubject> matches =
                    matchesBySubject.getOrDefault(
                            assertedSubject,
                            List.of());
            boolean hasActive = matches.stream().anyMatch(subject ->
                    subject.getStatus()
                            == IdentityBindingSubjectStatus.ACTIVE);
            if (hasActive) {
                continue;
            }
            List<IdentityBindingSubject> revoked = matches.stream()
                    .filter(subject -> subject.getStatus()
                            == IdentityBindingSubjectStatus.REVOKED)
                    .toList();
            if (revoked.isEmpty()) {
                continue;
            }
            if (assertedSubject.equals(assertion.primarySubject())) {
                throw accessDenied();
            }
            if (revoked.stream().anyMatch(subject ->
                    !bindingId.equals(subject.getBindingId()))) {
                throw identifierConflict();
            }
            revokedAliases.add(assertedSubject);
        }
        return new MatchResolution(
                bindingId,
                Set.copyOf(revokedAliases));
    }

    private IdentityLoginOutcome resolveExisting(
            IdentityAssertion assertion,
            ExternalSubject legacySubject,
            IdentityBinding binding,
            Set<ExternalSubject> revokedAliases,
            ProviderDescriptor descriptor,
            IdentityLoginContext context) {
        if (!binding.getProviderCode().equals(
                assertion.provider().providerCode())
                || !binding.getSubject().equals(legacySubject.value())) {
            throw identifierConflict();
        }

        UserAccount user = userRepository
                .findByIdForUpdate(binding.getUserId())
                .orElseThrow(() -> new IllegalStateException(
                        "User not found for identity binding"));
        AccountLoginDecision decision =
                accountLoginGuard.evaluateInteractive(user);
        if (decision != AccountLoginDecision.ALLOWED
                && decision != AccountLoginDecision.PENDING) {
            requireAllowed(decision);
        }

        requireAccessAllowed(
                assertion,
                context,
                IdentityAccessKind.RETURNING_IDENTITY,
                Optional.of(user.getStatus()));
        if (decision == AccountLoginDecision.PENDING) {
            reconcileSubjects(
                    binding,
                    assertion,
                    revokedAliases);
            binding.recordAuthentication(
                    assertion.evidence().authenticatedAt());
            bindingRepository.save(binding);
            recordAudit(
                    user.getId(),
                    "IDENTITY_LOGIN_PENDING",
                    binding.getId(),
                    assertion.provider().providerCode(),
                    "pending",
                    context);
            return new IdentityLoginOutcome.PendingApproval(
                    ACCOUNT_PENDING);
        }

        reconcileSubjects(
                binding,
                assertion,
                revokedAliases);
        binding.recordAuthentication(
                assertion.evidence().authenticatedAt());
        bindingRepository.save(binding);

        profileSyncService.synchronize(
                user,
                assertion,
                descriptor,
                false);
        user = userRepository.save(user);
        binding.recordSynchronization(
                assertion.evidence().authenticatedAt());
        bindingRepository.save(binding);
        recordAudit(
                user.getId(),
                "IDENTITY_LOGIN_SUCCEEDED",
                binding.getId(),
                assertion.provider().providerCode(),
                "authenticated",
                context);
        return new IdentityLoginOutcome.Authenticated(
                principalFactory.create(
                        user,
                        assertion.provider().providerCode()),
                false,
                false);
    }

    private void reconcileSubjects(
            IdentityBinding binding,
            IdentityAssertion assertion,
            Set<ExternalSubject> revokedAliases) {
        subjectRepository.demoteActivePrimary(
                binding.getId(),
                IdentityBindingSubjectStatus.ACTIVE);
        List<IdentityBindingSubject> activeSubjects =
                new ArrayList<>(
                        subjectRepository
                                .findByBindingIdAndStatusForUpdate(
                                        binding.getId(),
                                        IdentityBindingSubjectStatus.ACTIVE));
        boolean legacyManaged = activeSubjects.isEmpty()
                || activeSubjects.stream().anyMatch(subject ->
                        LEGACY_SUBJECT_TYPE.equals(
                                subject.getSubjectType()));
        Map<ExternalSubject, IdentityBindingSubject> existing =
                new HashMap<>();
        for (IdentityBindingSubject subject : activeSubjects) {
            IdentityBindingSubject duplicate = existing.put(
                    externalSubject(subject),
                    subject);
            if (duplicate != null) {
                throw identifierConflict();
            }
            subject.makeAlias();
        }

        Instant authenticatedAt =
                assertion.evidence().authenticatedAt();
        if (legacyManaged) {
            ExternalSubject compatibilitySubject =
                    new ExternalSubject(
                            LEGACY_SUBJECT_TYPE,
                            binding.getSubject());
            existing.computeIfAbsent(
                    compatibilitySubject,
                    ignored -> {
                        IdentityBindingSubject created =
                                new IdentityBindingSubject(
                                        binding.getId(),
                                        binding.getProviderCode(),
                                        compatibilitySubject.type(),
                                        compatibilitySubject.value(),
                                        false,
                                        authenticatedAt);
                        activeSubjects.add(created);
                        return created;
                    });
        }

        for (ExternalSubject assertedSubject :
                assertion.allSubjects()) {
            if (revokedAliases.contains(assertedSubject)) {
                continue;
            }
            IdentityBindingSubject subject = existing.computeIfAbsent(
                    assertedSubject,
                    ignored -> {
                        IdentityBindingSubject created =
                                new IdentityBindingSubject(
                                        binding.getId(),
                                        binding.getProviderCode(),
                                        assertedSubject.type(),
                                        assertedSubject.value(),
                                        false,
                                        authenticatedAt);
                        activeSubjects.add(created);
                        return created;
                    });
            subject.markSeen(authenticatedAt);
        }

        IdentityBindingSubject primary =
                existing.get(assertion.primarySubject());
        if (primary == null) {
            throw accessDenied();
        }
        primary.makePrimary();
        subjectRepository.saveAll(activeSubjects);
    }

    private IdentityLoginOutcome createAccount(
            IdentityAssertion assertion,
            ExternalSubject legacySubject,
            ProviderDescriptor descriptor,
            ProvisioningMode mode,
            IdentityLoginContext context) {
        if (mode == ProvisioningMode.EXISTING_BINDING_ONLY) {
            throw accessDenied();
        }

        Optional<String> email = trustedEmail(assertion.profile());
        if (email.filter(userRepository::existsByEmailIgnoreCase)
                .isPresent()) {
            recordAudit(
                    null,
                    "IDENTITY_EMAIL_COLLISION",
                    null,
                    assertion.provider().providerCode(),
                    "link_required",
                    context);
            return new IdentityLoginOutcome.LinkRequired(
                    EMAIL_COLLISION);
        }

        UserStatus initialStatus =
                mode == ProvisioningMode.APPROVAL
                        ? UserStatus.PENDING
                        : UserStatus.ACTIVE;
        String userId = "usr_" + UUID.randomUUID();
        UserAccount user = new UserAccount(
                userId,
                userId,
                null,
                null);
        user.setStatus(initialStatus);
        user = userRepository.save(user);

        profileSyncService.synchronize(
                user,
                assertion,
                descriptor,
                true);
        user = userRepository.save(user);

        if (initialStatus == UserStatus.ACTIVE) {
            membershipService.ensureMember(user.getId());
        }
        IdentityBinding binding = new IdentityBinding(
                user.getId(),
                assertion.provider().providerCode(),
                legacySubject.value(),
                assertion.profile().displayName());
        binding.recordAuthentication(
                assertion.evidence().authenticatedAt());
        IdentityBinding savedBinding =
                bindingRepository.save(binding);
        if (savedBinding.getId() == null) {
            throw new IllegalStateException(
                    "Identity binding id was not assigned");
        }

        List<IdentityBindingSubject> subjects =
                assertion.allSubjects().stream()
                        .map(subject -> new IdentityBindingSubject(
                                savedBinding.getId(),
                                savedBinding.getProviderCode(),
                                subject.type(),
                                subject.value(),
                                subject.equals(
                                        assertion.primarySubject()),
                                assertion.evidence()
                                        .authenticatedAt()))
                        .toList();
        subjectRepository.saveAll(subjects);

        if (initialStatus == UserStatus.PENDING) {
            recordAudit(
                    user.getId(),
                    "IDENTITY_PROVISIONING_PENDING",
                    savedBinding.getId(),
                    assertion.provider().providerCode(),
                    "pending",
                    context);
            return new IdentityLoginOutcome.PendingApproval(
                    ACCOUNT_PENDING);
        }
        requireAllowed(accountLoginGuard.evaluateInteractive(user));
        savedBinding.recordSynchronization(
                assertion.evidence().authenticatedAt());
        bindingRepository.save(savedBinding);
        recordAudit(
                user.getId(),
                "IDENTITY_ACCOUNT_PROVISIONED",
                savedBinding.getId(),
                assertion.provider().providerCode(),
                "authenticated",
                context);
        return new IdentityLoginOutcome.Authenticated(
                principalFactory.create(
                        user,
                        assertion.provider().providerCode()),
                true,
                true);
    }

    private Map<String, Set<String>> subjectValuesByType(
            Set<ExternalSubject> subjects) {
        LinkedHashMap<String, Set<String>> valuesByType =
                new LinkedHashMap<>();
        for (ExternalSubject subject : subjects) {
            valuesByType.computeIfAbsent(
                            subject.type(),
                            ignored -> new LinkedHashSet<>())
                    .add(subject.value());
        }
        return Map.copyOf(valuesByType);
    }

    private ExternalSubject externalSubject(
            IdentityBindingSubject subject) {
        return new ExternalSubject(
                subject.getSubjectType(),
                subject.getSubjectValue());
    }

    private Optional<String> trustedEmail(ExternalProfile profile) {
        return profile.email()
                .filter(claim -> claim.assurance()
                        .isVerifiedOrAuthoritative())
                .map(EmailClaim::value);
    }

    private void requireAccessAllowed(
            IdentityAssertion assertion,
            IdentityLoginContext context,
            IdentityAccessKind accessKind,
            Optional<UserStatus> accountStatus) {
        AccessDecision decision = accessPolicy.evaluate(
                new IdentityAccessContext(
                        assertion.provider().providerCode(),
                        assertion.primarySubject().type(),
                        assertion.primarySubject().value(),
                        assertion.profile().email()
                                .map(EmailClaim::value),
                        assertion.profile().email()
                                .map(EmailClaim::assurance)
                                .orElse(
                                        EmailAssurance.UNVERIFIED),
                        context,
                        accessKind,
                        accountStatus));
        if (decision == AccessDecision.DENY) {
            throw accessDenied();
        }
    }

    private void recordAudit(
            String actorUserId,
            String action,
            Long bindingId,
            String providerCode,
            String result,
            IdentityLoginContext context) {
        auditLogService.record(
                actorUserId,
                action,
                "IDENTITY_BINDING",
                bindingId,
                context.requestId(),
                context.clientIp(),
                context.userAgent(),
                "{\"providerCode\":\""
                        + providerCode
                        + "\",\"result\":\""
                        + result
                        + "\"}");
    }

    private void requireAllowed(AccountLoginDecision decision) {
        IdentityFailureCode failureCode = switch (decision) {
            case ALLOWED -> null;
            case PENDING -> IdentityFailureCode.ACCOUNT_PENDING;
            case DISABLED -> IdentityFailureCode.ACCOUNT_DISABLED;
            case MERGED -> IdentityFailureCode.ACCOUNT_MERGED;
            case SYSTEM_ACCOUNT ->
                    IdentityFailureCode.SYSTEM_ACCOUNT_FORBIDDEN;
        };
        if (failureCode != null) {
            throw new IdentityCoreException(failureCode);
        }
    }

    private IdentityCoreException identifierConflict() {
        return new IdentityCoreException(
                IdentityFailureCode.IDENTITY_IDENTIFIER_CONFLICT);
    }

    private IdentityCoreException accessDenied() {
        return new IdentityCoreException(
                IdentityFailureCode.ACCESS_DENIED);
    }

    private record MatchResolution(
            Long bindingId,
            Set<ExternalSubject> revokedAliases) {
    }
}
