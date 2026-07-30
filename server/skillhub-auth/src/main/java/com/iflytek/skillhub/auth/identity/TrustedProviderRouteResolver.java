package com.iflytek.skillhub.auth.identity;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Resolves only server-owned Spring Security client registrations into opaque
 * identity-core provider handles.
 */
public interface TrustedProviderRouteResolver {

    ResolvedProviderHandle resolve(ClientRegistration registration);
}
