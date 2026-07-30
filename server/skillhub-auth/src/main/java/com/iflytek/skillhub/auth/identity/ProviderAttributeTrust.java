package com.iflytek.skillhub.auth.identity;

/**
 * Trust level asserted by a protocol adapter for one upstream attribute.
 *
 * <p>The identity core always clamps this value to the configured provider
 * descriptor and never treats it as an authorization decision.</p>
 */
public enum ProviderAttributeTrust {
    UNVERIFIED,
    ASSERTED,
    VERIFIED
}
