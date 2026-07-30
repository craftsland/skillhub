package com.iflytek.skillhub.auth.provider;

import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;

/**
 * Active credential authentication capability, for example LDAP bind.
 */
public interface CredentialAuthenticationAdapter {

    ProviderInstanceDefinition provider();

    /**
     * @throws ProviderAuthenticationException for classified authentication
     *         or upstream failures
     */
    ProviderAuthenticationResult authenticate(
            CredentialAuthenticationRequest request);
}
