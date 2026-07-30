package com.iflytek.skillhub.auth.identity;

record SameAuthorityRecoveryEvaluation(
        boolean recovered,
        AuthorityLockEvaluation authority
) {
}
