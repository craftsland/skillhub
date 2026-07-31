package com.iflytek.skillhub.auth.cas;

import org.springframework.mock.env.MockEnvironment;

final class CasTestConfiguration {

    private CasTestConfiguration() {
    }

    static CasProperties validProperties() {
        CasProperties properties = new CasProperties();
        properties.setEnabled(true);
        properties.setProviderCode("cas-main");
        properties.setDisplayName("Corporate CAS");
        properties.setAuthority("corp-cas");
        properties.setServerUrl("https://cas.example.com/cas");
        properties.setServiceUrl(
                "https://skillhub.example.com/api/v1/auth/cas/cas-main/callback");
        properties.setProtocolVersion("3.0");
        return properties;
    }

    static CasProviderConfiguration configuration(
            CasProperties properties) {
        return new CasProviderConfiguration(
                properties,
                new MockEnvironment().withProperty(
                        "spring.profiles.active",
                        "test"));
    }
}
