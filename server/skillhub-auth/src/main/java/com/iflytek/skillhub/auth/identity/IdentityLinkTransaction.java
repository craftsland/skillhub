package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.entity.IdentityBinding;
import com.iflytek.skillhub.auth.entity.IdentityBindingStatus;
import com.iflytek.skillhub.auth.entity.IdentityBindingSubject;
import com.iflytek.skillhub.auth.entity.IdentityBindingSubjectStatus;
import com.iflytek.skillhub.auth.entity.IdentityLinkOperation;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequest;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import com.iflytek.skillhub.auth.local.LocalCredentialRepository;
import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.auth.repository.IdentityBindingSubjectRepository;
import com.iflytek.skillhub.auth.repository.IdentityLinkRequestRepository;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short PostgreSQL transaction for Identity Link request state, Binding V2
 * creation, and safe revocation. Protocol I/O and credential verification run
 * before these methods are invoked.
 */
@Service
class IdentityLinkTransaction {

    static final Duration INTENT_TTL = Duration.ofMinutes(10);
    private static final String USER_UNLINK_REASON =
            "User removed linked login method";

    private final IdentityLinkRequestRepository requestRepository;
    private final IdentityBindingRepository bindingRepository;
    private final IdentityBindingSubjectRepository subjectRepository;
    private final LocalCredentialRepository credentialRepository;
    private final UserAccountRepository userRepository;
    private final IdentityProviderRegistry providerRegistry;
    private final IdentityLinkStateHasher stateHasher;
    private final AccountLoginGuard accountLoginGuard;
    private final PlatformPrincipalFactory principalFactory;
    private final AuditLogService auditLogService;
    private final Clock clock;

    IdentityLinkTransaction(
            IdentityLinkRequestRepository requestRepository,
            IdentityBindingRepository bindingRepository,
            IdentityBindingSubjectRepository subjectRepository,
            LocalCredentialRepository credentialRepository,
            UserAccountRepository userRepository,
            IdentityProviderRegistry providerRegistry,
            IdentityLinkStateHasher stateHasher,
            AccountLoginGuard accountLoginGuard,
            PlatformPrincipalFactory principalFactory,
            AuditLogService auditLogService,
            Clock clock) {
        this.requestRepository = requestRepository;
        this.bindingRepository = bindingRepository;
        this.subjectRepository = subjectRepository;
        this.credentialRepository = credentialRepository;
        this.userRepository = userRepository;
        this.providerRegistry = providerRegistry;
        this.stateHasher = stateHasher;
        this.accountLoginGuard = accountLoginGuard;
        this.principalFactory = principalFactory;
        this.auditLogService = auditLogService;
        this.clock = clock;
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent createLinkIntent(
            IdentityLinkActor actor,
            UUID intentId,
            String providerCode) {
        Instant now = now();
        requireEligibleAccount(actor.userId());
        requireReadyLinkProvider(providerCode);
        boolean alreadyLinked = bindingRepository
                .findByUserIdAndStatus(
                        actor.userId(),
                        IdentityBindingStatus.ACTIVE)
                .stream()
                .anyMatch(binding -> binding.getProviderCode()
                        .equals(providerCode));
        if (alreadyLinked) {
            throw failure(IdentityLinkFailureCode.ALREADY_LINKED);
        }
        requireNoActiveRequest(actor, now);

        IdentityLinkRequest request = new IdentityLinkRequest(
                intentId,
                actor.userId(),
                IdentityLinkOperation.LINK,
                providerCode,
                null,
                stateHasher.hash(actor.sessionNonce()),
                now.plus(INTENT_TTL),
                now);
        requestRepository.saveAndFlush(request);
        recordAudit(
                actor,
                "IDENTITY_LINK_INTENT_CREATED",
                request,
                "pending_reauthentication");
        return toIntent(request);
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent createUnlinkIntent(
            IdentityLinkActor actor,
            UUID intentId,
            long bindingId) {
        Instant now = now();
        requireEligibleAccount(actor.userId());
        requireNoActiveRequest(actor, now);
        IdentityBinding binding = bindingRepository
                .findByIdAndStatusForUpdate(
                        bindingId,
                        IdentityBindingStatus.ACTIVE)
                .filter(candidate -> candidate.getUserId()
                        .equals(actor.userId()))
                .orElseThrow(() ->
                        failure(IdentityLinkFailureCode.INTENT_NOT_FOUND));

        IdentityLinkRequest request = new IdentityLinkRequest(
                intentId,
                actor.userId(),
                IdentityLinkOperation.UNLINK,
                binding.getProviderCode(),
                binding.getId(),
                stateHasher.hash(actor.sessionNonce()),
                now.plus(INTENT_TTL),
                now);
        requestRepository.saveAndFlush(request);
        recordAudit(
                actor,
                "IDENTITY_UNLINK_INTENT_CREATED",
                request,
                "pending_reauthentication");
        return toIntent(request);
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent getIntent(
            IdentityLinkActor actor,
            UUID intentId) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requireActive(request, actor);
        return toIntent(request);
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent cancel(
            IdentityLinkActor actor,
            UUID intentId) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requireActive(request, actor);
        request.cancel(now());
        recordAudit(
                actor,
                "IDENTITY_LINK_INTENT_CANCELLED",
                request,
                "cancelled");
        return toIntent(request);
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent markLocalReauthenticated(
            IdentityLinkActor actor,
            UUID intentId) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requirePendingReauthentication(request, actor);
        requireEligibleAccount(actor.userId());
        request.markReauthenticated("local-password", now());
        recordAudit(
                actor,
                "IDENTITY_LINK_ACCOUNT_REAUTHENTICATED",
                request,
                "local-password");
        return toIntent(request);
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent prepareExternalReauthentication(
            IdentityLinkActor actor,
            UUID intentId,
            String providerCode,
            IdentityProviderLoginMethodType methodType) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requirePendingReauthentication(request, actor);
        requireEligibleAccount(actor.userId());
        requireProviderCapability(
                actor,
                request,
                providerCode,
                methodType);
        boolean linked = bindingRepository
                .findByUserIdAndStatus(
                        actor.userId(),
                        IdentityBindingStatus.ACTIVE)
                .stream()
                .anyMatch(binding -> binding.getProviderCode()
                        .equals(providerCode));
        if (!linked) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        }
        return toIntent(request);
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent prepareExternalLink(
            IdentityLinkActor actor,
            UUID intentId,
            IdentityProviderLoginMethodType methodType) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requireReady(
                request,
                actor,
                IdentityLinkOperation.LINK);
        requireEligibleAccount(actor.userId());
        requireProviderCapability(
                actor,
                request,
                request.getProviderCode(),
                methodType);
        boolean alreadyLinked = bindingRepository
                .findByUserIdAndStatus(
                        actor.userId(),
                        IdentityBindingStatus.ACTIVE)
                .stream()
                .anyMatch(binding -> binding.getProviderCode()
                        .equals(request.getProviderCode()));
        if (alreadyLinked) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        }
        return toIntent(request);
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public PlatformPrincipal markExternalReauthenticated(
            IdentityLinkActor actor,
            UUID intentId,
            IdentityAssertion assertion,
            ProviderDescriptor descriptor) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requirePendingReauthentication(request, actor);
        UserAccount user = requireEligibleAccount(actor.userId());
        IdentityBinding binding = resolveAuthenticatedBinding(
                assertion,
                descriptor);
        if (!binding.getUserId().equals(actor.userId())) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.ACCOUNT_NOT_ELIGIBLE);
        }
        request.markReauthenticated(
                "provider:" + assertion.provider().providerCode(),
                now());
        recordAudit(
                actor,
                "IDENTITY_LINK_ACCOUNT_REAUTHENTICATED",
                request,
                assertion.provider().providerCode());
        return principalFactory.create(
                user,
                actor.authenticationProvider());
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public LinkedBinding link(
            IdentityLinkActor actor,
            UUID intentId,
            IdentityAssertion assertion,
            ProviderDescriptor descriptor) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requireReady(request, actor, IdentityLinkOperation.LINK);
        if (!request.getProviderCode().equals(
                assertion.provider().providerCode())
                || !request.getProviderCode().equals(
                descriptor.providerCode())) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.INVALID_OPERATION);
        }
        UserAccount user = requireEligibleAccount(actor.userId());
        boolean alreadyLinked = bindingRepository
                .findByUserIdAndStatus(
                        actor.userId(),
                        IdentityBindingStatus.ACTIVE)
                .stream()
                .anyMatch(binding -> binding.getProviderCode()
                        .equals(descriptor.providerCode()));
        if (alreadyLinked) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.ALREADY_LINKED);
        }
        requireSubjectsUnbound(
                actor,
                request,
                assertion,
                descriptor);

        ExternalSubject legacySubject = assertion.requireUniqueSubject(
                descriptor.legacyPrimarySubjectType());
        IdentityBinding binding = new IdentityBinding(
                actor.userId(),
                descriptor.providerCode(),
                legacySubject.value(),
                assertion.profile().displayName());
        binding.recordAuthentication(
                assertion.evidence().authenticatedAt());
        IdentityBinding savedBinding =
                bindingRepository.saveAndFlush(binding);
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
        subjectRepository.saveAllAndFlush(subjects);
        request.complete(now());
        recordAudit(
                actor,
                "IDENTITY_BINDING_LINKED",
                request,
                descriptor.providerCode());
        return new LinkedBinding(
                principalFactory.create(
                        user,
                        actor.authenticationProvider()),
                savedBinding.getId());
    }

    @Transactional(noRollbackFor = IdentityLinkException.class)
    public IdentityLinkIntent completeUnlink(
            IdentityLinkActor actor,
            UUID intentId) {
        IdentityLinkRequest request = requireRequest(
                actor,
                intentId);
        requireReady(
                request,
                actor,
                IdentityLinkOperation.UNLINK);
        requireEligibleAccount(actor.userId());
        IdentityBinding binding = bindingRepository
                .findByIdAndStatusForUpdate(
                        request.getTargetBindingId(),
                        IdentityBindingStatus.ACTIVE)
                .filter(candidate -> candidate.getUserId()
                        .equals(actor.userId()))
                .orElseThrow(() ->
                        reject(
                                actor,
                                request,
                                IdentityLinkFailureCode.ALREADY_CONSUMED));
        if (!hasOtherUsableLoginMethod(
                actor.userId(),
                binding.getId())) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.FINAL_LOGIN_METHOD);
        }

        Instant revokedAt = now();
        List<IdentityBindingSubject> activeSubjects =
                subjectRepository.findByBindingIdAndStatusForUpdate(
                        binding.getId(),
                        IdentityBindingSubjectStatus.ACTIVE);
        if (activeSubjects.isEmpty()) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.ALREADY_CONSUMED);
        }
        activeSubjects.forEach(subject ->
                subject.revoke(revokedAt));
        subjectRepository.saveAll(activeSubjects);
        binding.revoke(
                actor.userId(),
                USER_UNLINK_REASON,
                revokedAt);
        bindingRepository.save(binding);
        request.complete(revokedAt);
        recordAudit(
                actor,
                "IDENTITY_BINDING_REVOKED",
                request,
                binding.getProviderCode());
        return toIntent(request);
    }

    @Transactional(readOnly = true)
    public IdentityLinkAccountState accountState(String userId) {
        requireEligibleAccountForRead(userId);
        List<IdentityBinding> bindings = bindingRepository
                .findByUserIdAndStatus(
                        userId,
                        IdentityBindingStatus.ACTIVE)
                .stream()
                .sorted(Comparator.comparing(
                        IdentityBinding::getProviderCode))
                .toList();
        Map<String, ReadyProvider> readyProviders =
                readyProviders();
        boolean localPasswordEnabled =
                credentialRepository.existsByUserId(userId);
        long usableMethodCount =
                localPasswordEnabled ? 1 : 0;
        usableMethodCount += bindings.stream()
                .filter(binding -> readyProviders.containsKey(
                        binding.getProviderCode()))
                .count();

        long totalUsableMethodCount = usableMethodCount;
        List<IdentityLinkBindingView> linked =
                bindings.stream()
                        .map(binding -> {
                            ReadyProvider provider =
                                    readyProviders.get(
                                            binding.getProviderCode());
                            boolean usable = provider != null;
                            boolean anotherUsableMethod =
                                    totalUsableMethodCount
                                            - (usable ? 1 : 0)
                                            > 0;
                            return new IdentityLinkBindingView(
                                    binding.getId(),
                                    binding.getProviderCode(),
                                    provider == null
                                            ? binding.getProviderCode()
                                            : provider.displayName(),
                                    provider == null
                                            ? Set.of()
                                            : provider.methodTypes(),
                                    usable,
                                    anotherUsableMethod);
                        })
                        .toList();

        Set<String> linkedProviderCodes = bindings.stream()
                .map(IdentityBinding::getProviderCode)
                .collect(Collectors.toSet());
        List<IdentityLinkProviderView> available =
                readyProviders.values()
                        .stream()
                        .filter(provider ->
                                !linkedProviderCodes.contains(
                                        provider.providerCode()))
                        .filter(provider ->
                                provider.methodTypes().stream()
                                        .anyMatch(
                                                IdentityLinkTransaction
                                                        ::isLinkableMethod))
                        .sorted(Comparator.comparing(
                                ReadyProvider::providerCode))
                        .map(provider ->
                                new IdentityLinkProviderView(
                                        provider.providerCode(),
                                        provider.displayName(),
                                        provider.methodTypes()))
                        .toList();
        return new IdentityLinkAccountState(
                localPasswordEnabled,
                linked,
                available);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordRejectedAfterRollback(
            IdentityLinkActor actor,
            UUID intentId,
            IdentityLinkFailureCode code) {
        requestRepository.findById(intentId)
                .filter(request -> request.getPrimaryUserId()
                        .equals(actor.userId()))
                .filter(request -> stateHasher.matches(
                        actor.sessionNonce(),
                        request.getStateHash()))
                .ifPresent(request -> recordAudit(
                        actor,
                        "IDENTITY_LINK_INTENT_REJECTED",
                        request,
                        code.name().toLowerCase(Locale.ROOT)));
    }

    private IdentityLinkRequest requireRequest(
            IdentityLinkActor actor,
            UUID intentId) {
        IdentityLinkRequest request = requestRepository
                .findByIdForUpdate(intentId)
                .orElseThrow(() ->
                        failure(
                                IdentityLinkFailureCode
                                        .INTENT_NOT_FOUND));
        if (!request.getPrimaryUserId().equals(actor.userId())) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.INTENT_NOT_FOUND);
        }
        if (!stateHasher.matches(
                actor.sessionNonce(),
                request.getStateHash())) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.SESSION_MISMATCH);
        }
        return request;
    }

    private void requireActive(
            IdentityLinkRequest request,
            IdentityLinkActor actor) {
        if (request.getStatus() == IdentityLinkRequestStatus.EXPIRED) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.INTENT_EXPIRED);
        }
        if (!request.getStatus().isActive()) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.ALREADY_CONSUMED);
        }
        if (request.isExpiredAt(now())) {
            request.expire(now());
            recordAudit(
                    actor,
                    "IDENTITY_LINK_INTENT_EXPIRED",
                    request,
                    "expired");
            throw failure(
                    IdentityLinkFailureCode.INTENT_EXPIRED);
        }
    }

    private void requirePendingReauthentication(
            IdentityLinkRequest request,
            IdentityLinkActor actor) {
        requireActive(request, actor);
        if (request.getStatus()
                != IdentityLinkRequestStatus
                        .PENDING_REAUTHENTICATION) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.ALREADY_CONSUMED);
        }
    }

    private void requireReady(
            IdentityLinkRequest request,
            IdentityLinkActor actor,
            IdentityLinkOperation operation) {
        requireActive(request, actor);
        if (request.getOperation() != operation) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.INVALID_OPERATION);
        }
        if (request.getStatus() != IdentityLinkRequestStatus.READY) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.REAUTHENTICATION_REQUIRED);
        }
    }

    private UserAccount requireEligibleAccount(String userId) {
        UserAccount user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(() ->
                        failure(
                                IdentityLinkFailureCode
                                        .ACCOUNT_NOT_ELIGIBLE));
        if (accountLoginGuard.evaluateInteractive(user)
                != AccountLoginDecision.ALLOWED) {
            throw failure(
                    IdentityLinkFailureCode.ACCOUNT_NOT_ELIGIBLE);
        }
        return user;
    }

    private UserAccount requireEligibleAccountForRead(String userId) {
        UserAccount user = userRepository.findById(userId)
                .orElseThrow(() ->
                        failure(
                                IdentityLinkFailureCode
                                        .ACCOUNT_NOT_ELIGIBLE));
        if (accountLoginGuard.evaluateInteractive(user)
                != AccountLoginDecision.ALLOWED) {
            throw failure(
                    IdentityLinkFailureCode.ACCOUNT_NOT_ELIGIBLE);
        }
        return user;
    }

    private void requireReadyLinkProvider(String providerCode) {
        if (providerCode == null || providerCode.isBlank()) {
            throw failure(
                    IdentityLinkFailureCode.INVALID_OPERATION);
        }
        ReadyProvider provider = readyProviders().get(providerCode);
        if (provider == null
                || provider.methodTypes().stream()
                        .noneMatch(
                                IdentityLinkTransaction
                                        ::isLinkableMethod)) {
            throw failure(
                    IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        }
    }

    private static boolean isLinkableMethod(
            IdentityProviderLoginMethodType methodType) {
        return methodType
                == IdentityProviderLoginMethodType.OAUTH_REDIRECT
                || methodType
                == IdentityProviderLoginMethodType.CAS_REDIRECT
                || methodType
                == IdentityProviderLoginMethodType.DIRECT_PASSWORD;
    }

    private void requireProviderCapability(
            IdentityLinkActor actor,
            IdentityLinkRequest request,
            String providerCode,
            IdentityProviderLoginMethodType methodType) {
        ReadyProvider provider =
                readyProviders().get(providerCode);
        if (provider == null
                || !provider.methodTypes().contains(methodType)) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        }
    }

    private Map<String, ReadyProvider> readyProviders() {
        Map<String, ProviderAccumulator> accumulated =
                new LinkedHashMap<>();
        for (IdentityProviderLoginMethod method
                : providerRegistry.listReadyLoginMethods()) {
            accumulated.computeIfAbsent(
                            method.providerCode(),
                            ignored -> new ProviderAccumulator(
                                    method.providerCode(),
                                    method.displayName()))
                    .methodTypes()
                    .add(method.methodType());
        }
        LinkedHashMap<String, ReadyProvider> providers =
                new LinkedHashMap<>();
        accumulated.values().forEach(provider ->
                providers.put(
                        provider.providerCode(),
                        new ReadyProvider(
                                provider.providerCode(),
                                provider.displayName(),
                                Set.copyOf(
                                        provider.methodTypes()))));
        return Map.copyOf(providers);
    }

    private IdentityBinding resolveAuthenticatedBinding(
            IdentityAssertion assertion,
            ProviderDescriptor descriptor) {
        List<IdentityBindingSubject> typedMatches =
                subjectRepository.findMatchingSubjects(
                        assertion.provider().providerCode(),
                        subjectValuesByType(assertion.allSubjects()));
        ExternalSubject legacySubject = assertion.requireUniqueSubject(
                descriptor.legacyPrimarySubjectType());
        IdentityBinding legacyMatch = bindingRepository
                .findByProviderCodeAndSubjectAndStatus(
                        assertion.provider().providerCode(),
                        legacySubject.value(),
                        IdentityBindingStatus.ACTIVE)
                .orElse(null);

        LinkedHashSet<Long> activeBindingIds = typedMatches.stream()
                .filter(subject -> subject.getStatus()
                        == IdentityBindingSubjectStatus.ACTIVE)
                .map(IdentityBindingSubject::getBindingId)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (legacyMatch != null
                && legacyMatch.getStatus()
                        == IdentityBindingStatus.ACTIVE) {
            activeBindingIds.add(legacyMatch.getId());
        }
        if (activeBindingIds.size() != 1) {
            throw failure(
                    IdentityLinkFailureCode.ACCOUNT_NOT_ELIGIBLE);
        }
        return bindingRepository
                .findByIdAndStatusForUpdate(
                        activeBindingIds.getFirst(),
                        IdentityBindingStatus.ACTIVE)
                .orElseThrow(() ->
                        failure(
                                IdentityLinkFailureCode
                                        .ACCOUNT_NOT_ELIGIBLE));
    }

    private void requireSubjectsUnbound(
            IdentityLinkActor actor,
            IdentityLinkRequest request,
            IdentityAssertion assertion,
            ProviderDescriptor descriptor) {
        List<IdentityBindingSubject> matches =
                subjectRepository.findMatchingSubjects(
                        assertion.provider().providerCode(),
                        subjectValuesByType(assertion.allSubjects()));
        ExternalSubject legacySubject = assertion.requireUniqueSubject(
                descriptor.legacyPrimarySubjectType());
        boolean activeSubjectExists = matches.stream()
                .anyMatch(subject -> subject.getStatus()
                        == IdentityBindingSubjectStatus.ACTIVE);
        boolean activeLegacyBindingExists = bindingRepository
                .findByProviderCodeAndSubjectAndStatus(
                        assertion.provider().providerCode(),
                        legacySubject.value(),
                        IdentityBindingStatus.ACTIVE)
                .isPresent();
        if (activeSubjectExists || activeLegacyBindingExists) {
            throw reject(
                    actor,
                    request,
                    IdentityLinkFailureCode.IDENTITY_IN_USE);
        }
    }

    private void requireNoActiveRequest(
            IdentityLinkActor actor,
            Instant now) {
        requestRepository
                .findActiveByPrimaryUserIdForUpdate(
                        actor.userId(),
                        Set.of(
                                IdentityLinkRequestStatus
                                        .PENDING_REAUTHENTICATION,
                                IdentityLinkRequestStatus.READY))
                .ifPresent(active -> {
                    if (!active.isExpiredAt(now)) {
                        throw reject(
                                actor,
                                active,
                                IdentityLinkFailureCode
                                        .ACTIVE_INTENT_EXISTS);
                    }
                    active.expire(now);
                    recordAudit(
                            actor,
                            "IDENTITY_LINK_INTENT_EXPIRED",
                            active,
                            "expired");
                    requestRepository.flush();
                });
    }

    private boolean hasOtherUsableLoginMethod(
            String userId,
            long excludedBindingId) {
        if (credentialRepository.existsByUserId(userId)) {
            return true;
        }
        Set<String> readyProviderCodes =
                readyProviders().keySet();
        return bindingRepository
                .findByUserIdAndStatus(
                        userId,
                        IdentityBindingStatus.ACTIVE)
                .stream()
                .filter(binding -> binding.getId()
                        != excludedBindingId)
                .map(IdentityBinding::getProviderCode)
                .anyMatch(readyProviderCodes::contains);
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

    private void recordAudit(
            IdentityLinkActor actor,
            String action,
            IdentityLinkRequest request,
            String result) {
        IdentityLoginContext context = actor.auditContext();
        auditLogService.record(
                actor.userId(),
                action,
                "IDENTITY_LINK_REQUEST",
                null,
                context.requestId(),
                context.clientIp(),
                context.userAgent(),
                "{\"intentId\":\""
                        + request.getId()
                        + "\",\"operation\":\""
                        + request.getOperation()
                        + "\",\"providerCode\":\""
                        + request.getProviderCode()
                        + "\",\"result\":\""
                        + result
                        + "\"}");
    }

    private IdentityLinkIntent toIntent(IdentityLinkRequest request) {
        return new IdentityLinkIntent(
                request.getId(),
                request.getOperation(),
                request.getStatus(),
                request.getProviderCode(),
                request.getTargetBindingId(),
                request.getExpiresAt());
    }

    private Instant now() {
        return Instant.now(clock);
    }

    private IdentityLinkException failure(
            IdentityLinkFailureCode code) {
        return new IdentityLinkException(code);
    }

    private IdentityLinkException reject(
            IdentityLinkActor actor,
            IdentityLinkRequest request,
            IdentityLinkFailureCode code) {
        recordAudit(
                actor,
                "IDENTITY_LINK_INTENT_REJECTED",
                request,
                code.name().toLowerCase(Locale.ROOT));
        return failure(code);
    }

    record LinkedBinding(
            PlatformPrincipal principal,
            long bindingId) {
    }

    private record ReadyProvider(
            String providerCode,
            String displayName,
            Set<IdentityProviderLoginMethodType> methodTypes) {
    }

    private record ProviderAccumulator(
            String providerCode,
            String displayName,
            Set<IdentityProviderLoginMethodType> methodTypes) {
        private ProviderAccumulator(
                String providerCode,
                String displayName) {
            this(
                    providerCode,
                    displayName,
                    new LinkedHashSet<>());
        }
    }
}
