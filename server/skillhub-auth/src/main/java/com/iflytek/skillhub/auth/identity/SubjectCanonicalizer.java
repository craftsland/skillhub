package com.iflytek.skillhub.auth.identity;

import java.util.regex.Pattern;

enum SubjectCanonicalizer {
    EXACT {
        @Override
        String canonicalize(String value) {
            validateCommon(value);
            return value;
        }
    },
    DECIMAL {
        private final Pattern decimal = Pattern.compile("[0-9]+");

        @Override
        String canonicalize(String value) {
            validateCommon(value);
            if (!decimal.matcher(value).matches()) {
                throw invalidAssertion();
            }
            return value;
        }
    };

    abstract String canonicalize(String value);

    static void validateCommon(String value) {
        if (value == null
                || value.isBlank()
                || value.length() > ProviderAssertionLimits.MAX_SUBJECT_VALUE_LENGTH
                || value.chars().anyMatch(Character::isISOControl)) {
            throw invalidAssertion();
        }
    }

    private static IdentityCoreException invalidAssertion() {
        return new IdentityCoreException(IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }
}
