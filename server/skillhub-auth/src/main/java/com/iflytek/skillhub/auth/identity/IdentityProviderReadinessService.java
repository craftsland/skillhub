package com.iflytek.skillhub.auth.identity;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Fail-closed gate for a server-owned interactive identity provider route.
 */
public interface IdentityProviderReadinessService {

    void requireReady(ClientRegistration registration);
}
