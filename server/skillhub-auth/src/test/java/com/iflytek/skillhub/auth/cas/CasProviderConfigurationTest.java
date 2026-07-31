package com.iflytek.skillhub.auth.cas;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class CasProviderConfigurationTest {

    @Test
    void resolvesStableAuthorityAndProtocolEndpoints() {
        CasProviderConfiguration.ResolvedCasProvider resolved =
                CasTestConfiguration.configuration(
                        CasTestConfiguration.validProperties())
                        .requireResolved();

        assertThat(resolved.providerCode()).isEqualTo("cas-main");
        assertThat(resolved.authority()).isEqualTo("corp-cas");
        assertThat(resolved.serverUri().toString())
                .isEqualTo("https://cas.example.com/cas");
        assertThat(resolved.protocolVersion())
                .isEqualTo(CasProtocolVersion.V3_0);
        assertThat(resolved.subjectType())
                .isEqualTo("cas_principal");
    }

    @Test
    void productionCannotEnablePlainHttpEscapeHatch() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setServerUrl("http://cas.example.com/cas");
        properties.setServiceUrl(
                "http://skillhub.example.com/api/v1/auth/cas/cas-main/callback");
        properties.setAllowInsecureForTesting(true);
        CasProviderConfiguration configuration =
                new CasProviderConfiguration(
                        properties,
                        new MockEnvironment().withProperty(
                                "spring.profiles.active",
                                "prod"));

        assertThatThrownBy(configuration::requireResolved)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid CAS provider configuration");
    }

    @Test
    void stagingCanExplicitlyUseHttpForAnIsolatedFixture() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setServerUrl("http://127.0.0.1:18080/cas");
        properties.setServiceUrl(
                "http://127.0.0.1:18081/api/v1/auth/cas/cas-main/callback");
        properties.setAllowInsecureForTesting(true);
        CasProviderConfiguration configuration =
                new CasProviderConfiguration(
                        properties,
                        new MockEnvironment().withProperty(
                                "spring.profiles.active",
                                "staging"));

        assertThat(configuration.requireResolved().serverUri()
                .getScheme()).isEqualTo("http");
    }

    @Test
    void rejectsUnstableAuthorityAndWrongCallbackPath() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setAuthority("Corporate CAS");

        assertThatThrownBy(() -> CasTestConfiguration
                .configuration(properties)
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);

        properties.setAuthority("corp-cas");
        properties.setServiceUrl(
                "https://skillhub.example.com/api/v1/auth/cas/callback");

        assertThatThrownBy(() -> CasTestConfiguration
                .configuration(properties)
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsQueryFragmentsAndInvalidExplicitPorts() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setServerUrl(
                "https://cas.example.com/cas?tenant=corp");

        assertThatThrownBy(() -> CasTestConfiguration
                .configuration(properties)
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);

        properties.setServerUrl("https://cas.example.com:0/cas");

        assertThatThrownBy(() -> CasTestConfiguration
                .configuration(properties)
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsUnboundedTimeoutsAndPayloads() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setReadTimeout(Duration.ofMinutes(2));

        assertThatThrownBy(() -> CasTestConfiguration
                .configuration(properties)
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);

        properties.setReadTimeout(Duration.ofSeconds(10));
        properties.setMaxResponseBytes(1024 * 1024 + 1);

        assertThatThrownBy(() -> CasTestConfiguration
                .configuration(properties)
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
