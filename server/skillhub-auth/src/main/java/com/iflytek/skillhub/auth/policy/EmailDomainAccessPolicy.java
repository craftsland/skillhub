package com.iflytek.skillhub.auth.policy;

import java.util.Locale;
import java.util.Set;

/**
 * Access policy that allows login only when the OAuth email belongs to an approved domain.
 */
public class EmailDomainAccessPolicy implements AccessPolicy {
    private final Set<String> allowedDomains;

    public EmailDomainAccessPolicy(Set<String> allowedDomains) {
        this.allowedDomains = allowedDomains;
    }

    @Override
    public AccessDecision evaluate(IdentityAccessContext context) {
        if (context.email().isEmpty()
                || !context.emailAssurance().isVerifiedOrAuthoritative()) {
            return AccessDecision.DENY;
        }
        String email = context.email().orElseThrow();
        int separator = email.lastIndexOf('@');
        if (separator <= 0 || separator == email.length() - 1) {
            return AccessDecision.DENY;
        }
        String domain = email.substring(separator + 1);
        return allowedDomains.contains(domain.toLowerCase(Locale.ROOT))
            ? AccessDecision.ALLOW : AccessDecision.DENY;
    }
}
