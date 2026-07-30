package com.iflytek.skillhub.auth.identity;

final class ProviderAssertionLimits {
    static final int MAX_SUBJECT_VALUE_LENGTH = 256;
    static final int MAX_ATTRIBUTE_COUNT = 64;
    static final int MAX_VALUES_PER_ATTRIBUTE = 16;
    static final int MAX_ATTRIBUTE_VALUE_LENGTH = 2_048;
    static final int MAX_TOTAL_PAYLOAD_LENGTH = 32_768;

    private ProviderAssertionLimits() {
    }
}
