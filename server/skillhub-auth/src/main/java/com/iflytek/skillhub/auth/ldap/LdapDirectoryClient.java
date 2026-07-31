package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;

/**
 * Performs LDAP protocol I/O before the platform identity transaction starts.
 */
@FunctionalInterface
interface LdapDirectoryClient {

    LdapAuthenticatedEntry authenticate(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            CredentialAuthenticationRequest request);
}
