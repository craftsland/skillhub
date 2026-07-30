package com.iflytek.skillhub.auth.policy;

/**
 * Policy contract for deciding whether externally authenticated users may enter the platform.
 */
public interface AccessPolicy {
    AccessDecision evaluate(IdentityAccessContext context);
}
