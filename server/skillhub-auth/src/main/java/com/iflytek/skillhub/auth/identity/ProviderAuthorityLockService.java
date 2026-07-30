package com.iflytek.skillhub.auth.identity;

import org.springframework.stereotype.Service;

@Service
class ProviderAuthorityLockService {

    private final ProviderAuthorityStateTransaction stateTransaction;

    ProviderAuthorityLockService(
            ProviderAuthorityStateTransaction stateTransaction) {
        this.stateTransaction = stateTransaction;
    }

    void requirePinnedAuthority(ProviderDescriptor descriptor) {
        String fingerprint = fingerprint(descriptor);
        AuthorityLockEvaluation evaluation =
                stateTransaction.pin(descriptor, fingerprint);
        if (evaluation.ready()) {
            return;
        }
        if (evaluation.state()
                == IdentityProviderStatus.AUTHORITY_MISMATCH) {
            throw new IdentityCoreException(
                    IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH);
        }
        throw new IdentityCoreException(
                IdentityFailureCode.PROVIDER_DISABLED);
    }

    boolean isReady(ProviderDescriptor descriptor) {
        AuthorityLockEvaluation evaluation =
                stateTransaction.read(descriptor.providerCode());
        return evaluation.ready()
                && fingerprint(descriptor)
                        .equals(evaluation.persistedFingerprint());
    }

    SameAuthorityRecoveryEvaluation recoverSameAuthority(
            ProviderDescriptor descriptor,
            IdentityProviderAuthorityRecoveryContext context) {
        return stateTransaction.recoverSameAuthority(
                descriptor,
                fingerprint(descriptor),
                context);
    }

    private String fingerprint(ProviderDescriptor descriptor) {
        return ProviderAuthorityFingerprint.sha256(
                descriptor.protocol(),
                descriptor.canonicalAuthority());
    }
}
