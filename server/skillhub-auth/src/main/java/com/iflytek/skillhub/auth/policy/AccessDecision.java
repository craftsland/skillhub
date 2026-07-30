package com.iflytek.skillhub.auth.policy;

/**
 * Per-login access decision. First-login provisioning is decided separately
 * by the provisioning policy.
 */
public enum AccessDecision {
    ALLOW,
    DENY
}
