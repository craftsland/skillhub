package com.iflytek.skillhub.auth.merge;

import java.util.Objects;
import java.util.UUID;

/**
 * One-time, session-bound browser provider flow.
 */
public sealed interface AccountMergeBrowserFlow
        permits AccountMergeBrowserFlow.Primary,
                AccountMergeBrowserFlow.Secondary {

    String primaryUserId();

    String providerCode();

    record Primary(
            String primaryUserId,
            String providerCode
    ) implements AccountMergeBrowserFlow {
        public Primary {
            primaryUserId = requireText(
                    primaryUserId,
                    "primaryUserId",
                    128);
            providerCode = requireText(
                    providerCode,
                    "providerCode",
                    64);
        }
    }

    record Secondary(
            UUID intentId,
            AccountMergeActor actor,
            String providerCode
    ) implements AccountMergeBrowserFlow {
        public Secondary {
            Objects.requireNonNull(intentId, "intentId");
            Objects.requireNonNull(actor, "actor");
            providerCode = requireText(
                    providerCode,
                    "providerCode",
                    64);
        }

        @Override
        public String primaryUserId() {
            return actor.userId();
        }
    }

    private static String requireText(
            String value,
            String fieldName,
            int maximumLength) {
        if (value == null
                || value.isBlank()
                || value.length() > maximumLength) {
            throw new IllegalArgumentException(
                    "Invalid account merge browser flow "
                            + fieldName);
        }
        return value;
    }
}
