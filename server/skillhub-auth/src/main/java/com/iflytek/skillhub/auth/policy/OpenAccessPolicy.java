package com.iflytek.skillhub.auth.policy;

/**
 * Access policy that accepts all OAuth-authenticated users.
 */
public class OpenAccessPolicy implements AccessPolicy {
    @Override
    public AccessDecision evaluate(IdentityAccessContext context) {
        return AccessDecision.ALLOW;
    }
}
