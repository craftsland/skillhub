package com.iflytek.skillhub.auth.policy;

import java.util.Set;

/**
 * Access policy that only permits a configured set of provider-subject pairs.
 */
public class SubjectWhitelistAccessPolicy implements AccessPolicy {
    private final Set<String> whitelistedSubjects;

    public SubjectWhitelistAccessPolicy(Set<String> whitelistedSubjects) {
        this.whitelistedSubjects = whitelistedSubjects;
    }

    @Override
    public AccessDecision evaluate(IdentityAccessContext context) {
        String key = context.providerCode() + ":" + context.subjectValue();
        return whitelistedSubjects.contains(key)
            ? AccessDecision.ALLOW : AccessDecision.DENY;
    }
}
