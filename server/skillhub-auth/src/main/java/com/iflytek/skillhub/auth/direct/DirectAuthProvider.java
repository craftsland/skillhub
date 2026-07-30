package com.iflytek.skillhub.auth.direct;

import com.iflytek.skillhub.auth.provider.CredentialAuthenticationAdapter;

/**
 * Compatibility name for credential adapters.
 *
 * @deprecated implement {@link CredentialAuthenticationAdapter} directly.
 */
@Deprecated(forRemoval = true)
public interface DirectAuthProvider
        extends CredentialAuthenticationAdapter {
}
