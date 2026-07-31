package com.iflytek.skillhub.auth.ldap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.SelfSignedCertificateGenerator;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustStoreTrustManager;
import java.io.File;
import java.net.InetAddress;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class UnboundIdLdapDirectoryClientTest {

    private static final Instant AUTHENTICATED_AT =
            Instant.parse("2026-07-31T10:00:00Z");

    private InMemoryDirectoryServer directory;
    private UnboundIdLdapDirectoryClient client;
    private File tlsKeyStore;

    @BeforeEach
    void setUp() throws Exception {
        startDirectory(null);
        client = new UnboundIdLdapDirectoryClient(
                Clock.fixed(AUTHENTICATED_AT, ZoneOffset.UTC));
    }

    private void startDirectory(InMemoryListenerConfig listener)
            throws Exception {
        InMemoryDirectoryServerConfig serverConfiguration =
                new InMemoryDirectoryServerConfig(
                        "dc=example,dc=com");
        if (listener != null) {
            serverConfiguration.setListenerConfigs(listener);
        }
        serverConfiguration.setSchema(null);
        serverConfiguration.setGenerateOperationalAttributes(true);
        serverConfiguration.addAdditionalBindCredentials(
                "cn=reader,dc=example,dc=com",
                "reader-password");
        directory = new InMemoryDirectoryServer(serverConfiguration);
        directory.startListening();
        directory.add(
                "dn: dc=example,dc=com",
                "objectClass: top",
                "objectClass: domain",
                "dc: example");
        directory.add(
                "dn: ou=people,dc=example,dc=com",
                "objectClass: top",
                "objectClass: organizationalUnit",
                "ou: people");
        directory.add(
                "dn: uid=alice,ou=people,dc=example,dc=com",
                "objectClass: top",
                "objectClass: person",
                "objectClass: inetOrgPerson",
                "uid: alice",
                "cn: Alice Directory",
                "sn: Directory",
                "displayName: Alice Directory",
                "mail: alice@example.com",
                "userPassword: alice-password");
    }

    @AfterEach
    void tearDown() {
        if (client != null) {
            client.close();
        }
        if (directory != null) {
            directory.shutDown(true);
        }
        if (tlsKeyStore != null) {
            try {
                Files.deleteIfExists(tlsKeyStore.toPath());
            } catch (Exception ignored) {
                // Test-only best-effort cleanup.
            }
        }
    }

    @Test
    void authenticatesUniqueOpenLdapEntryAndReturnsStableFacts() {
        LdapAuthenticatedEntry entry = client.authenticate(
                provider(),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password"));

        assertThat(entry.subject())
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        + "[0-9a-f]{4}-[0-9a-f]{12}");
        assertThat(entry.attributes())
                .containsEntry("uid", java.util.List.of("alice"))
                .containsEntry(
                        "displayName",
                        java.util.List.of("Alice Directory"))
                .containsEntry(
                        "mail",
                        java.util.List.of("alice@example.com"));
        assertThat(entry.authenticatedAt()).isEqualTo(AUTHENTICATED_AT);
    }

    @Test
    void distinguishesUnknownIdentityFromInvalidPasswordWithoutDetails() {
        assertFailure(
                "unknown",
                "irrelevant-password",
                ProviderAuthenticationFailureCode
                        .UPSTREAM_IDENTITY_NOT_FOUND);
        assertFailure(
                "alice",
                "wrong-password",
                ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_CREDENTIALS);
    }

    @Test
    void escapesUsernameBeforeSubstitutingSearchFilter() {
        assertFailure(
                "*)(uid=*)",
                "alice-password",
                ProviderAuthenticationFailureCode
                        .UPSTREAM_IDENTITY_NOT_FOUND);
    }

    @Test
    void rejectsAmbiguousSearchResult() throws Exception {
        directory.add(
                "dn: uid=bob,ou=people,dc=example,dc=com",
                "objectClass: top",
                "objectClass: person",
                "objectClass: inetOrgPerson",
                "uid: bob",
                "cn: Bob Directory",
                "sn: Directory",
                "userPassword: bob-password");

        assertThatThrownBy(() -> client.authenticate(
                provider(
                        "OPENLDAP",
                        "(|(uid={0})(objectClass=inetOrgPerson))",
                        null,
                        null),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password")))
                .isInstanceOfSatisfying(
                        ProviderAuthenticationException.class,
                        failure -> assertThat(failure.getReasonCode())
                                .isEqualTo(
                                        ProviderAuthenticationFailureCode
                                                .UPSTREAM_INVALID_RESPONSE));
    }

    @Test
    void rejectsEntryWithoutConfiguredStableSubject() {
        assertThatThrownBy(() -> client.authenticate(
                provider(
                        "CUSTOM",
                        "(uid={0})",
                        "immutableId",
                        "custom_immutable_id"),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password")))
                .isInstanceOfSatisfying(
                        ProviderAuthenticationException.class,
                        failure -> assertThat(failure.getReasonCode())
                                .isEqualTo(
                                        ProviderAuthenticationFailureCode
                                                .UPSTREAM_INVALID_RESPONSE));
    }

    @Test
    void convertsActiveDirectoryObjectGuidUsingFixedByteOrder()
            throws Exception {
        directory.modify(
                "uid=alice,ou=people,dc=example,dc=com",
                new Modification(
                        ModificationType.ADD,
                        "objectGUID",
                        new byte[]{
                                0x33, 0x22, 0x11, 0x00,
                                0x55, 0x44,
                                0x77, 0x66,
                                (byte) 0x88, (byte) 0x99,
                                (byte) 0xaa, (byte) 0xbb,
                                (byte) 0xcc, (byte) 0xdd,
                                (byte) 0xee, (byte) 0xff
                        }));

        LdapAuthenticatedEntry entry = client.authenticate(
                provider(
                        "ACTIVE_DIRECTORY",
                        "(uid={0})",
                        null,
                        null),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password"));

        assertThat(entry.subject())
                .isEqualTo("00112233-4455-6677-8899-aabbccddeeff");
    }

    @Test
    void classifiesDirectoryTimeoutAsUnavailable() {
        directory.setProcessingDelayMillis(250);

        assertThatThrownBy(() -> client.authenticate(
                provider(
                        "OPENLDAP",
                        "(uid={0})",
                        null,
                        null,
                        Duration.ofMillis(50)),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password")))
                .isInstanceOfSatisfying(
                        ProviderAuthenticationException.class,
                        failure -> assertThat(failure.getReasonCode())
                                .isEqualTo(
                                        ProviderAuthenticationFailureCode
                                                .UPSTREAM_UNAVAILABLE));
    }

    @Test
    void classifiesUnavailableDirectoryWithoutLeakingEndpoint() {
        int closedPort = directory.getListenPort();
        directory.shutDown(true);

        assertThatThrownBy(() -> client.authenticate(
                provider(
                        "OPENLDAP",
                        "(uid={0})",
                        null,
                        null,
                        Duration.ofMillis(100),
                        closedPort),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password")))
                .isInstanceOfSatisfying(
                        ProviderAuthenticationException.class,
                        failure -> {
                            assertThat(failure.getReasonCode())
                                    .isEqualTo(
                                            ProviderAuthenticationFailureCode
                                                    .UPSTREAM_UNAVAILABLE);
                            assertThat(failure.getMessage())
                                    .isEqualTo("UPSTREAM_UNAVAILABLE");
                        });
    }

    @Test
    void supportsLdapsWithTrustedCertificate() throws Exception {
        TlsMaterial tls = tlsMaterial();
        InetAddress tlsAddress = InetAddress.getLocalHost();
        restartDirectory(InMemoryListenerConfig.createLDAPSConfig(
                "ldaps",
                tlsAddress,
                0,
                tls.serverSocketFactory(),
                tls.clientSocketFactory()));
        client = trustedTlsClient(tls);

        LdapAuthenticatedEntry entry = client.authenticate(
                provider(
                        "ldaps://" + endpointHost(tlsAddress) + ":"
                                + directory.getListenPort(),
                        false),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password"));

        assertThat(entry.subject())
                .matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}");
    }

    @Test
    void supportsStartTlsWithTrustedCertificate() throws Exception {
        TlsMaterial tls = tlsMaterial();
        InetAddress tlsAddress = InetAddress.getLocalHost();
        restartDirectory(InMemoryListenerConfig.createLDAPConfig(
                "starttls",
                tlsAddress,
                0,
                tls.serverTlsSocketFactory()));
        client = trustedTlsClient(tls);

        LdapAuthenticatedEntry entry = client.authenticate(
                provider(
                        "ldap://" + endpointHost(tlsAddress) + ":"
                                + directory.getListenPort(),
                        true),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password"));

        assertThat(entry.subject()).isNotBlank();
    }

    @Test
    void rejectsUntrustedLdapsCertificate() throws Exception {
        TlsMaterial tls = tlsMaterial();
        InetAddress tlsAddress = InetAddress.getLocalHost();
        restartDirectory(InMemoryListenerConfig.createLDAPSConfig(
                "ldaps",
                tlsAddress,
                0,
                tls.serverSocketFactory(),
                tls.clientSocketFactory()));

        assertThatThrownBy(() -> client.authenticate(
                provider(
                        "ldaps://" + endpointHost(tlsAddress) + ":"
                                + directory.getListenPort(),
                        false),
                new CredentialAuthenticationRequest(
                        "alice",
                        "alice-password")))
                .isInstanceOfSatisfying(
                        ProviderAuthenticationException.class,
                        failure -> assertThat(failure.getReasonCode())
                                .isEqualTo(
                                        ProviderAuthenticationFailureCode
                                                .TLS_VALIDATION_FAILED));
    }

    private void assertFailure(
            String username,
            String password,
            ProviderAuthenticationFailureCode expected) {
        assertThatThrownBy(() -> client.authenticate(
                provider(),
                new CredentialAuthenticationRequest(
                        username,
                        password)))
                .isInstanceOfSatisfying(
                        ProviderAuthenticationException.class,
                        failure -> {
                            assertThat(failure.getReasonCode())
                                    .isEqualTo(expected);
                            assertThat(failure.getMessage())
                                    .isEqualTo(expected.name());
                        });
    }

    private LdapProviderConfiguration.ResolvedLdapProvider provider() {
        return provider("OPENLDAP", "(uid={0})", null, null);
    }

    private LdapProviderConfiguration.ResolvedLdapProvider provider(
            String directoryType,
            String searchFilter,
            String subjectAttribute,
            String subjectType) {
        return provider(
                directoryType,
                searchFilter,
                subjectAttribute,
                subjectType,
                Duration.ofSeconds(10));
    }

    private LdapProviderConfiguration.ResolvedLdapProvider provider(
            String directoryType,
            String searchFilter,
            String subjectAttribute,
            String subjectType,
            Duration readTimeout) {
        return provider(
                directoryType,
                searchFilter,
                subjectAttribute,
                subjectType,
                readTimeout,
                directory.getListenPort());
    }

    private LdapProviderConfiguration.ResolvedLdapProvider provider(
            String directoryType,
            String searchFilter,
            String subjectAttribute,
            String subjectType,
            Duration readTimeout,
            int port) {
        LdapProperties properties = new LdapProperties();
        properties.setEnabled(true);
        properties.setProviderCode("corporate-ldap");
        properties.setDisplayName("Corporate Directory");
        properties.setAuthority("corp-directory-v1");
        properties.setUrl(
                "ldap://127.0.0.1:" + port);
        properties.setAllowInsecureForTesting(true);
        properties.setBaseDn("dc=example,dc=com");
        properties.setUserSearchBase("ou=people");
        properties.setBindDn("cn=reader,dc=example,dc=com");
        properties.setBindPassword("reader-password");
        properties.setDirectoryType(directoryType);
        properties.setUserSearchFilter(searchFilter);
        properties.setSubjectAttribute(subjectAttribute);
        properties.setSubjectType(subjectType);
        properties.setConnectTimeout(readTimeout);
        properties.setReadTimeout(readTimeout);
        return new LdapProviderConfiguration(
                properties,
                new MockEnvironment().withProperty(
                        "spring.profiles.active",
                        "test"))
                .requireResolved();
    }

    private LdapProviderConfiguration.ResolvedLdapProvider provider(
            String endpoint,
            boolean startTls) {
        LdapProperties properties = new LdapProperties();
        properties.setEnabled(true);
        properties.setProviderCode("corporate-ldap");
        properties.setDisplayName("Corporate Directory");
        properties.setAuthority("corp-directory-v1");
        properties.setUrl(endpoint);
        properties.setStartTls(startTls);
        properties.setBaseDn("dc=example,dc=com");
        properties.setUserSearchBase("ou=people");
        properties.setBindDn("cn=reader,dc=example,dc=com");
        properties.setBindPassword("reader-password");
        return new LdapProviderConfiguration(
                properties,
                new MockEnvironment().withProperty(
                        "spring.profiles.active",
                        "test"))
                .requireResolved();
    }

    private void restartDirectory(InMemoryListenerConfig listener)
            throws Exception {
        client.close();
        directory.shutDown(true);
        startDirectory(listener);
    }

    private UnboundIdLdapDirectoryClient trustedTlsClient(
            TlsMaterial tls) {
        return new UnboundIdLdapDirectoryClient(
                Clock.fixed(AUTHENTICATED_AT, ZoneOffset.UTC),
                tls::clientSocketFactory);
    }

    private String endpointHost(InetAddress address) {
        String host = address.getHostAddress();
        return host.contains(":") ? "[" + host + "]" : host;
    }

    private TlsMaterial tlsMaterial() throws Exception {
        ObjectPair<File, char[]> generated =
                SelfSignedCertificateGenerator
                        .generateTemporarySelfSignedCertificate(
                                "SkillHub LDAP test",
                                "JKS");
        tlsKeyStore = generated.getFirst();
        char[] password = generated.getSecond();
        KeyStoreKeyManager keyManager = new KeyStoreKeyManager(
                tlsKeyStore,
                password,
                "JKS",
                "server-cert");
        TrustStoreTrustManager trustManager =
                new TrustStoreTrustManager(
                        tlsKeyStore,
                        password,
                        "JKS",
                        true);
        SSLUtil serverSsl = new SSLUtil(keyManager, trustManager);
        return new TlsMaterial(
                serverSsl.createSSLServerSocketFactory(),
                serverSsl.createSSLSocketFactory(),
                new SSLUtil(trustManager).createSSLSocketFactory());
    }

    private record TlsMaterial(
            SSLServerSocketFactory serverSocketFactory,
            SSLSocketFactory serverTlsSocketFactory,
            SSLSocketFactory clientSocketFactory
    ) {
    }
}
