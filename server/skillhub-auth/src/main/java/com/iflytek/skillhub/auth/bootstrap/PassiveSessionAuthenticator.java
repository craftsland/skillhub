package com.iflytek.skillhub.auth.bootstrap;

import com.iflytek.skillhub.auth.provider.PassiveAuthenticationAdapter;

/**
 * Compatibility name for passive request adapters.
 *
 * @deprecated implement {@link PassiveAuthenticationAdapter} directly.
 */
@Deprecated(forRemoval = true)
public interface PassiveSessionAuthenticator
        extends PassiveAuthenticationAdapter {
}
