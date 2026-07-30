package com.iflytek.skillhub.auth.identity;

record AuthorityLockEvaluation(
        IdentityProviderStatus state,
        String persistedFingerprint
) {
    boolean ready() {
        return state == IdentityProviderStatus.READY;
    }
}
