package com.iflytek.skillhub.auth.ldap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class LdapProviderConfigurationTest {

    @Test
    void resolvesOpenLdapProviderWithStableEntryUuidSubject() {
        LdapProperties properties = validProperties();

        LdapProviderConfiguration.ResolvedLdapProvider resolved =
                new LdapProviderConfiguration(
                        properties,
                        new MockEnvironment().withProperty(
                                "spring.profiles.active",
                                "prod"))
                        .requireResolved();

        assertThat(resolved.providerCode())
                .isEqualTo("corporate-ldap");
        assertThat(resolved.authority())
                .isEqualTo("corp-directory-v1");
        assertThat(resolved.subjectAttribute())
                .isEqualTo("entryUUID");
        assertThat(resolved.subjectType())
                .isEqualTo("ldap_entry_uuid");
        assertThat(resolved.transport())
                .isEqualTo(LdapTransport.LDAPS);
    }

    @Test
    void resolvesActiveDirectoryObjectGuidSubjectType() {
        LdapProperties properties = validProperties();
        properties.setDirectoryType("ACTIVE_DIRECTORY");

        LdapProviderConfiguration.ResolvedLdapProvider resolved =
                configuration(properties, "prod").requireResolved();

        assertThat(resolved.subjectAttribute()).isEqualTo("objectGUID");
        assertThat(resolved.subjectType()).isEqualTo("ad_object_guid");
    }

    @Test
    void allowsPlainLdapOnlyWithExplicitNonProductionEscapeHatch() {
        LdapProperties properties = validProperties();
        properties.setUrl("ldap://ldap.example.com:389");
        properties.setAllowInsecureForTesting(true);

        assertThat(configuration(properties, "test")
                .requireResolved().transport())
                .isEqualTo(LdapTransport.PLAIN);
        assertThatThrownBy(() -> configuration(properties, "prod")
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid LDAP provider configuration");
    }

    @Test
    void rejectsMalformedDnAndSearchFilterBeforeAnyNetworkCall() {
        LdapProperties invalidDn = validProperties();
        invalidDn.setBaseDn("not-a-dn");
        assertThatThrownBy(() -> configuration(invalidDn, "prod")
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);

        LdapProperties invalidFilter = validProperties();
        invalidFilter.setUserSearchFilter("(&(uid={0})");
        assertThatThrownBy(() -> configuration(invalidFilter, "prod")
                .requireResolved())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void resolvedProviderStringDoesNotExposeBindPassword() {
        LdapProperties properties = validProperties();

        Object resolved = configuration(properties, "prod")
                .requireResolved();

        assertThat(resolved.toString())
                .doesNotContain("fixture-password")
                .doesNotContain("bindPassword");
    }

    private static LdapProviderConfiguration configuration(
            LdapProperties properties,
            String profile) {
        return new LdapProviderConfiguration(
                properties,
                new MockEnvironment().withProperty(
                        "spring.profiles.active",
                        profile));
    }

    private static LdapProperties validProperties() {
        LdapProperties properties = new LdapProperties();
        properties.setEnabled(true);
        properties.setProviderCode("corporate-ldap");
        properties.setDisplayName("Corporate Directory");
        properties.setAuthority("corp-directory-v1");
        properties.setUrl("ldaps://ldap.example.com:636");
        properties.setBaseDn("dc=example,dc=com");
        properties.setBindDn("cn=reader,dc=example,dc=com");
        properties.setBindPassword("fixture-password");
        return properties;
    }
}
