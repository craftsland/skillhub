package com.iflytek.skillhub.auth.policy;

/**
 * Login-policy contract evaluated for both new and returning external
 * identities. It does not decide whether a new account is auto-provisioned or
 * requires approval.
 */
public interface AccessPolicy {
    AccessDecision evaluate(IdentityAccessContext context);
}
