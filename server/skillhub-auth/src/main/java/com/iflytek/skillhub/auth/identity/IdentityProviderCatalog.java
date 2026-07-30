package com.iflytek.skillhub.auth.identity;

import java.util.List;

/**
 * Read-only projection of external identity providers that are safe to expose
 * as interactive login methods.
 */
public interface IdentityProviderCatalog {

    List<IdentityProviderLoginMethod> listReadyProviders();
}
