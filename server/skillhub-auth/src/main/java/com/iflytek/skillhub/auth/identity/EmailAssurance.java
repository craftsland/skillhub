package com.iflytek.skillhub.auth.identity;

/**
 * Assurance retained by the identity core after clamping adapter facts to the
 * trusted provider descriptor.
 */
public enum EmailAssurance {
    UNVERIFIED,
    PROVIDER_ASSERTED,
    VERIFIED,
    AUTHORITATIVE;

    EmailAssurance clampTo(EmailAssurance maximum) {
        return ordinal() <= maximum.ordinal() ? this : maximum;
    }

    public boolean isVerifiedOrAuthoritative() {
        return this == VERIFIED || this == AUTHORITATIVE;
    }
}
