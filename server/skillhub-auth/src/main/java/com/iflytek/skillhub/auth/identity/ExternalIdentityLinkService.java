package com.iflytek.skillhub.auth.identity;

import java.util.UUID;

/**
 * Unified facade for external fresh reauthentication and explicit Identity
 * Link. Protocol adapters provide verified external facts only.
 */
public interface ExternalIdentityLinkService {

    IdentityLinkOutcome reauthenticate(
            IdentityLinkActor actor,
            UUID intentId,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result);

    IdentityLinkOutcome link(
            IdentityLinkActor actor,
            UUID intentId,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result);
}
