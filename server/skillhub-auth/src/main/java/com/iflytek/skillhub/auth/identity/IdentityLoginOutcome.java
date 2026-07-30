package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.Objects;

/**
 * Business outcomes of the external identity transaction.
 */
public sealed interface IdentityLoginOutcome {

    record Authenticated(
            PlatformPrincipal principal,
            boolean accountCreated,
            boolean bindingCreated
    ) implements IdentityLoginOutcome {
        public Authenticated {
            Objects.requireNonNull(principal, "principal");
        }
    }

    record PendingApproval(
            String reasonCode
    ) implements IdentityLoginOutcome {
        public PendingApproval {
            requireReasonCode(reasonCode);
        }
    }

    record LinkRequired(
            String reasonCode
    ) implements IdentityLoginOutcome {
        public LinkRequired {
            requireReasonCode(reasonCode);
        }
    }

    private static void requireReasonCode(String reasonCode) {
        Objects.requireNonNull(reasonCode, "reasonCode");
        if (reasonCode.isBlank() || reasonCode.length() > 64) {
            throw new IllegalArgumentException("Invalid identity reason code");
        }
    }
}
