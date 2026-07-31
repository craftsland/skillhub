package com.iflytek.skillhub.auth.identity;

import java.util.UUID;

public record IdentityLinkBrowserFlow(
        UUID intentId,
        IdentityLinkBrowserPhase phase,
        IdentityLinkActor actor
) {
}
