package com.iflytek.skillhub.auth.cas;

/**
 * Application-facing CAS browser protocol boundary.
 */
public interface CasBrowserClient {

    CasLoginInitiation begin(
            String providerCode,
            String state);

    CasAuthenticationExchange validate(
            String providerCode,
            String ticket,
            String expectedServiceUrl);
}
