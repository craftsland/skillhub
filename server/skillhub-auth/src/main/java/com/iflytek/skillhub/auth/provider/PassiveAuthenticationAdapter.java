package com.iflytek.skillhub.auth.provider;

import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import java.util.Optional;

/**
 * Passive request authentication capability, for example a trusted gateway
 * assertion. Implementations receive an immutable request snapshot without
 * access to the servlet session or security context.
 */
public interface PassiveAuthenticationAdapter {

    ProviderInstanceDefinition provider();

    /**
     * @return an authenticated identity, or empty when the request carries no
     *         external authentication
     * @throws ProviderAuthenticationException when an assertion is present
     *         but invalid, replayed, or cannot be verified
     */
    Optional<ProviderAuthenticationResult> authenticate(
            PassiveAuthenticationRequest request);
}
