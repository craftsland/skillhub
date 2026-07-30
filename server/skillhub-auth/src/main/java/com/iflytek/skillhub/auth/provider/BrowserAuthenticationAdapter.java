package com.iflytek.skillhub.auth.provider;

import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;

/**
 * Converts one protocol-specific, already verified browser exchange into
 * provider facts. The transport flow retains ownership of redirects,
 * callbacks, state and session handling.
 *
 * @param <T> protocol-specific verified exchange type
 */
public interface BrowserAuthenticationAdapter<T> {

    /**
     * @throws ProviderAuthenticationException when the verified exchange
     *         cannot be accepted or its upstream is unavailable
     */
    ProviderAuthenticationResult authenticate(T exchange);
}
