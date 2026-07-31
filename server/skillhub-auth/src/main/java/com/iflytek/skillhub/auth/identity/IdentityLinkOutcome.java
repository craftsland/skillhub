package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.Objects;

public sealed interface IdentityLinkOutcome {

    record Reauthenticated(
            PlatformPrincipal principal
    ) implements IdentityLinkOutcome {
        public Reauthenticated {
            Objects.requireNonNull(principal, "principal");
        }
    }

    record Linked(
            PlatformPrincipal principal,
            long bindingId
    ) implements IdentityLinkOutcome {
        public Linked {
            Objects.requireNonNull(principal, "principal");
            if (bindingId <= 0) {
                throw new IllegalArgumentException(
                        "Identity binding id must be positive");
            }
        }
    }
}
