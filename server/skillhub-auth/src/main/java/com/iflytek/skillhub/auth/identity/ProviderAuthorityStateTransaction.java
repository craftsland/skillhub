package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
class ProviderAuthorityStateTransaction {

    private final IdentityProviderStateRepository stateRepository;
    private final IdentityBindingRepository bindingRepository;
    private final AuditLogService auditLogService;

    ProviderAuthorityStateTransaction(
            IdentityProviderStateRepository stateRepository,
            IdentityBindingRepository bindingRepository,
            AuditLogService auditLogService) {
        this.stateRepository = stateRepository;
        this.bindingRepository = bindingRepository;
        this.auditLogService = auditLogService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuthorityLockEvaluation pin(
            ProviderDescriptor descriptor,
            String expectedFingerprint) {
        Optional<IdentityProviderState> existing =
                stateRepository.findById(descriptor.providerCode());
        if (existing.isEmpty()) {
            createInitialState(descriptor, expectedFingerprint);
            existing = stateRepository.findById(descriptor.providerCode());
        }

        IdentityProviderState state = existing.orElseThrow(
                () -> new IllegalStateException(
                        "Provider authority state was not persisted"));
        if (state.getState() == IdentityProviderStatus.LEGACY_UNPINNED) {
            if (!descriptor.protocol().equals(state.getProtocol())) {
                stateRepository.markLegacyProtocolMismatch(
                        descriptor.providerCode(),
                        descriptor.protocol());
            } else {
                stateRepository.pinLegacy(
                        descriptor.providerCode(),
                        descriptor.protocol(),
                        descriptor.canonicalAuthority(),
                        expectedFingerprint);
            }
            state = reread(descriptor.providerCode());
        }

        if (state.getState() == IdentityProviderStatus.AUTHORITY_MISMATCH) {
            return evaluation(state);
        }

        if (state.getState() == IdentityProviderStatus.READY
                && descriptor.protocol().equals(state.getProtocol())
                && expectedFingerprint.equals(state.getAuthorityFingerprint())) {
            int touched = stateRepository.touchReady(
                    descriptor.providerCode(),
                    descriptor.protocol(),
                    expectedFingerprint);
            if (touched == 0) {
                state = reread(descriptor.providerCode());
            }
            return evaluation(state);
        }

        if ((state.getState() == IdentityProviderStatus.READY
                || state.getState() == IdentityProviderStatus.DEGRADED)
                && (!descriptor.protocol().equals(state.getProtocol())
                || !expectedFingerprint.equals(state.getAuthorityFingerprint()))) {
            stateRepository.markAuthorityMismatch(
                    descriptor.providerCode(),
                    descriptor.protocol(),
                    expectedFingerprint);
            state = reread(descriptor.providerCode());
        }
        return evaluation(state);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    public AuthorityLockEvaluation read(String providerCode) {
        return stateRepository.findById(providerCode)
                .map(this::evaluation)
                .orElse(new AuthorityLockEvaluation(
                        IdentityProviderStatus.MISCONFIGURED,
                        null));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public SameAuthorityRecoveryEvaluation recoverSameAuthority(
            ProviderDescriptor descriptor,
            String expectedFingerprint,
            IdentityProviderAuthorityRecoveryContext context) {
        int updated = stateRepository.recoverSameAuthority(
                descriptor.providerCode(),
                descriptor.protocol(),
                expectedFingerprint);
        AuthorityLockEvaluation authority = stateRepository
                .findById(descriptor.providerCode())
                .map(this::evaluation)
                .orElse(new AuthorityLockEvaluation(
                        IdentityProviderStatus.MISCONFIGURED,
                        null));
        boolean recovered = updated == 1
                && authority.ready()
                && expectedFingerprint.equals(
                        authority.persistedFingerprint());
        if (recovered) {
            auditLogService.record(
                    context.actorUserId(),
                    "PROVIDER_AUTHORITY_RECOVERED",
                    "IDENTITY_PROVIDER",
                    null,
                    context.requestId(),
                    context.clientIp(),
                    context.userAgent(),
                    recoveryDetail(descriptor, expectedFingerprint));
        }
        return new SameAuthorityRecoveryEvaluation(
                recovered,
                authority);
    }

    private void createInitialState(
            ProviderDescriptor descriptor,
            String expectedFingerprint) {
        if (bindingRepository.existsByProviderCode(descriptor.providerCode())) {
            stateRepository.insertLegacyUnpinned(
                    descriptor.providerCode(),
                    descriptor.protocol());
            return;
        }
        stateRepository.insertReady(
                descriptor.providerCode(),
                descriptor.protocol(),
                descriptor.canonicalAuthority(),
                expectedFingerprint);
    }

    private IdentityProviderState reread(String providerCode) {
        return stateRepository.findById(providerCode).orElseThrow(
                () -> new IllegalStateException(
                        "Provider authority state disappeared"));
    }

    private AuthorityLockEvaluation evaluation(IdentityProviderState state) {
        return new AuthorityLockEvaluation(
                state.getState(),
                state.getAuthorityFingerprint());
    }

    private String recoveryDetail(
            ProviderDescriptor descriptor,
            String fingerprint) {
        return "{\"providerCode\":\""
                + descriptor.providerCode()
                + "\",\"protocol\":\""
                + descriptor.protocol()
                + "\",\"authorityFingerprint\":\""
                + fingerprint
                + "\"}";
    }
}
