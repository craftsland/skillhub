package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PostConnectProcessor;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.SSLUtil;
import jakarta.annotation.PreDestroy;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.SocketFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * UnboundID-backed LDAP protocol client with a lazily initialized service
 * connection pool.
 */
@Component
final class UnboundIdLdapDirectoryClient
        implements LdapDirectoryClient, AutoCloseable {

    private static final int SEARCH_RESULT_LIMIT = 2;
    private static final int MAX_MESSAGE_SIZE_BYTES = 1024 * 1024;
    private static final int MAX_ATTRIBUTE_VALUE_LENGTH = 8192;

    private final Clock clock;
    private final TlsSocketFactorySource tlsSocketFactorySource;
    private volatile PoolHolder poolHolder;

    @Autowired
    UnboundIdLdapDirectoryClient() {
        this(
                Clock.systemUTC(),
                UnboundIdLdapDirectoryClient
                        ::jvmDefaultTlsSocketFactory);
    }

    UnboundIdLdapDirectoryClient(Clock clock) {
        this(
                clock,
                UnboundIdLdapDirectoryClient
                        ::jvmDefaultTlsSocketFactory);
    }

    UnboundIdLdapDirectoryClient(
            Clock clock,
            TlsSocketFactorySource tlsSocketFactorySource) {
        this.clock = clock;
        this.tlsSocketFactorySource = tlsSocketFactorySource;
    }

    @Override
    public LdapAuthenticatedEntry authenticate(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            CredentialAuthenticationRequest request) {
        requireCredentials(request);
        PoolHolder holder = requirePool(provider);
        SearchResultEntry entry = findUniqueEntry(
                holder.pool(),
                provider,
                request.username());
        verifyUserPassword(
                holder,
                entry.getDN(),
                request.password());
        return authenticatedEntry(provider, entry);
    }

    private SearchResultEntry findUniqueEntry(
            LDAPConnectionPool pool,
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            String username) {
        SearchRequest request;
        try {
            String searchBase = searchBase(provider);
            String escapedUsername = Filter.encodeValue(username);
            Filter filter = Filter.create(
                    provider.userSearchFilter().replace(
                            "{0}",
                            escapedUsername));
            request = new SearchRequest(
                    searchBase,
                    SearchScope.SUB,
                    DereferencePolicy.NEVER,
                    SEARCH_RESULT_LIMIT,
                    timeLimitSeconds(provider.readTimeout()),
                    false,
                    filter,
                    provider.requestedAttributes()
                            .toArray(String[]::new));
        } catch (LDAPException exception) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_MISCONFIGURED,
                    exception);
        }

        SearchResult result;
        try {
            result = pool.search(request);
        } catch (LDAPException exception) {
            throw classify(exception, FailurePhase.SEARCH);
        }
        if (result.getEntryCount() == 0) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_IDENTITY_NOT_FOUND);
        }
        if (result.getEntryCount() != 1) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_RESPONSE);
        }
        return result.getSearchEntries().getFirst();
    }

    private void verifyUserPassword(
            PoolHolder holder,
            String userDn,
            String password) {
        try (LDAPConnection connection =
                     holder.serverSet().getConnection()) {
            if (holder.postConnectProcessor() != null) {
                holder.postConnectProcessor()
                        .processPreAuthenticatedConnection(connection);
            }
            connection.bind(new SimpleBindRequest(userDn, password));
        } catch (LDAPException exception) {
            throw classify(exception, FailurePhase.USER_BIND);
        }
    }

    private LdapAuthenticatedEntry authenticatedEntry(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            SearchResultEntry entry) {
        String subject = subject(provider, entry);
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        for (String attributeName : provider.requestedAttributes()) {
            String[] values = entry.getAttributeValues(attributeName);
            if (values == null) {
                continue;
            }
            if (values.length > provider.maximumAttributeValues()) {
                throw failure(
                        ProviderAuthenticationFailureCode
                                .UPSTREAM_INVALID_RESPONSE);
            }
            List<String> copied = Arrays.stream(values)
                    .filter(value -> value != null
                            && value.length()
                            <= MAX_ATTRIBUTE_VALUE_LENGTH)
                    .toList();
            if (copied.size() != values.length) {
                throw failure(
                        ProviderAuthenticationFailureCode
                                .UPSTREAM_INVALID_RESPONSE);
            }
            attributes.put(attributeName, copied);
        }
        return new LdapAuthenticatedEntry(
                subject,
                attributes,
                clock.instant());
    }

    private String subject(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            SearchResultEntry entry) {
        return switch (provider.directoryType()) {
            case OPENLDAP -> openLdapSubject(provider, entry);
            case ACTIVE_DIRECTORY -> activeDirectorySubject(
                    provider,
                    entry);
            case CUSTOM -> customSubject(provider, entry);
        };
    }

    private String openLdapSubject(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            SearchResultEntry entry) {
        String value = uniqueTextSubject(provider, entry);
        try {
            return UUID.fromString(value).toString();
        } catch (IllegalArgumentException exception) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_RESPONSE,
                    exception);
        }
    }

    private String activeDirectorySubject(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            SearchResultEntry entry) {
        byte[][] values = entry.getAttributeValueByteArrays(
                provider.subjectAttribute());
        if (values == null || values.length != 1
                || values[0].length != 16) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_RESPONSE);
        }
        byte[] value = values[0];
        return "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
                .formatted(
                        unsigned(value[3]),
                        unsigned(value[2]),
                        unsigned(value[1]),
                        unsigned(value[0]),
                        unsigned(value[5]),
                        unsigned(value[4]),
                        unsigned(value[7]),
                        unsigned(value[6]))
                + "%02x%02x-%02x%02x%02x%02x%02x%02x"
                .formatted(
                        unsigned(value[8]),
                        unsigned(value[9]),
                        unsigned(value[10]),
                        unsigned(value[11]),
                        unsigned(value[12]),
                        unsigned(value[13]),
                        unsigned(value[14]),
                        unsigned(value[15]));
    }

    private String customSubject(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            SearchResultEntry entry) {
        return uniqueTextSubject(provider, entry);
    }

    private String uniqueTextSubject(
            LdapProviderConfiguration.ResolvedLdapProvider provider,
            SearchResultEntry entry) {
        String[] values = entry.getAttributeValues(
                provider.subjectAttribute());
        if (values == null || values.length != 1
                || values[0] == null
                || values[0].isBlank()
                || values[0].length() > 4096
                || values[0].chars().anyMatch(Character::isISOControl)) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_RESPONSE);
        }
        return values[0];
    }

    private int unsigned(byte value) {
        return Byte.toUnsignedInt(value);
    }

    private String searchBase(
            LdapProviderConfiguration.ResolvedLdapProvider provider)
            throws LDAPException {
        String value = provider.userSearchBase().isEmpty()
                ? provider.baseDn()
                : provider.userSearchBase() + "," + provider.baseDn();
        return new DN(value).toString();
    }

    private int timeLimitSeconds(Duration timeout) {
        long milliseconds = timeout.toMillis();
        return Math.toIntExact(Math.max(
                1,
                Math.ceilDiv(milliseconds, 1000)));
    }

    private PoolHolder requirePool(
            LdapProviderConfiguration.ResolvedLdapProvider provider) {
        PoolHolder current = poolHolder;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (poolHolder == null) {
                poolHolder = createPool(provider);
            }
            return poolHolder;
        }
    }

    private PoolHolder createPool(
            LdapProviderConfiguration.ResolvedLdapProvider provider) {
        try {
            LDAPConnectionOptions options = connectionOptions(provider);
            SSLSocketFactory tlsSocketFactory = null;
            SocketFactory socketFactory = SocketFactory.getDefault();
            PostConnectProcessor postConnectProcessor = null;
            if (provider.transport() != LdapTransport.PLAIN) {
                tlsSocketFactory = tlsSocketFactorySource.create();
            }
            if (provider.transport() == LdapTransport.LDAPS) {
                socketFactory = tlsSocketFactory;
            } else if (provider.transport()
                    == LdapTransport.STARTTLS) {
                postConnectProcessor =
                        new StartTLSPostConnectProcessor(
                                tlsSocketFactory);
            }

            SingleServerSet serverSet = new SingleServerSet(
                    provider.endpoint().getHost(),
                    endpointPort(provider),
                    socketFactory,
                    options);
            LDAPConnectionPool pool = new LDAPConnectionPool(
                    serverSet,
                    new SimpleBindRequest(
                            provider.bindDn(),
                            provider.bindPassword()),
                    0,
                    provider.maximumConcurrentRequests(),
                    postConnectProcessor);
            pool.setCreateIfNecessary(true);
            pool.setMaxWaitTimeMillis(
                    provider.poolWaitTimeout().toMillis());
            pool.setRetryFailedOperationsDueToInvalidConnections(false);
            pool.setConnectionPoolName(
                    "skillhub-ldap-" + provider.providerCode());
            return new PoolHolder(
                    serverSet,
                    pool,
                    postConnectProcessor);
        } catch (LDAPException exception) {
            throw classify(exception, FailurePhase.SERVICE_BIND);
        } catch (GeneralSecurityException exception) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .TLS_VALIDATION_FAILED,
                    exception);
        }
    }

    private LDAPConnectionOptions connectionOptions(
            LdapProviderConfiguration.ResolvedLdapProvider provider) {
        LDAPConnectionOptions options = new LDAPConnectionOptions();
        options.setConnectTimeoutMillis(
                Math.toIntExact(provider.connectTimeout().toMillis()));
        options.setResponseTimeoutMillis(
                provider.readTimeout().toMillis());
        options.setAbandonOnTimeout(true);
        options.setFollowReferrals(false);
        options.setUseSchema(false);
        options.setMaxMessageSize(MAX_MESSAGE_SIZE_BYTES);
        options.setSSLSocketVerifier(
                new HostNameSSLSocketVerifier(true));
        return options;
    }

    private static SSLSocketFactory jvmDefaultTlsSocketFactory()
            throws GeneralSecurityException {
        return new SSLUtil(JVMDefaultTrustManager.getInstance())
                .createSSLSocketFactory();
    }

    private int endpointPort(
            LdapProviderConfiguration.ResolvedLdapProvider provider) {
        if (provider.endpoint().getPort() > 0) {
            return provider.endpoint().getPort();
        }
        return provider.transport() == LdapTransport.LDAPS
                ? 636
                : 389;
    }

    private ProviderAuthenticationException classify(
            LDAPException exception,
            FailurePhase phase) {
        if (hasTlsCause(exception)) {
            return failure(
                    ProviderAuthenticationFailureCode
                            .TLS_VALIDATION_FAILED,
                    exception);
        }
        ResultCode code = exception.getResultCode();
        if (code == ResultCode.INVALID_CREDENTIALS) {
            return failure(
                    phase == FailurePhase.USER_BIND
                            ? ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_CREDENTIALS
                            : ProviderAuthenticationFailureCode
                            .UPSTREAM_MISCONFIGURED,
                    exception);
        }
        if (code == ResultCode.INSUFFICIENT_ACCESS_RIGHTS
                || code == ResultCode.AUTH_METHOD_NOT_SUPPORTED
                || code == ResultCode.STRONG_AUTH_REQUIRED
                || code == ResultCode.CONFIDENTIALITY_REQUIRED
                || code == ResultCode.INVALID_DN_SYNTAX
                || code == ResultCode.FILTER_ERROR
                || code == ResultCode.PARAM_ERROR
                || code == ResultCode.NO_SUCH_OBJECT) {
            return failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_MISCONFIGURED,
                    exception);
        }
        if (code == ResultCode.SIZE_LIMIT_EXCEEDED
                || code == ResultCode.ADMIN_LIMIT_EXCEEDED
                || code == ResultCode.DECODING_ERROR
                || code == ResultCode.PROTOCOL_ERROR) {
            return failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_RESPONSE,
                    exception);
        }
        return failure(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_UNAVAILABLE,
                exception);
    }

    private boolean hasTlsCause(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof SSLException
                    || current instanceof java.security.cert
                    .CertificateException) {
                return true;
            }
            if (current instanceof LDAPException ldapException) {
                String detail = ldapException.getExceptionMessage()
                        .toLowerCase(Locale.ROOT);
                if (detail.contains("hostname verification failed")
                        || detail.contains("tls negotiation")
                        || detail.contains("ssl handshake")
                        || detail.contains("certificate path")) {
                    return true;
                }
            }
            if (current.getCause() == current) {
                break;
            }
            current = current.getCause();
        }
        return false;
    }

    private void requireCredentials(
            CredentialAuthenticationRequest request) {
        if (request == null
                || request.username() == null
                || request.username().isBlank()
                || request.password() == null
                || request.password().isBlank()) {
            throw failure(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_CREDENTIALS);
        }
    }

    private ProviderAuthenticationException failure(
            ProviderAuthenticationFailureCode code) {
        return new ProviderAuthenticationException(code);
    }

    private ProviderAuthenticationException failure(
            ProviderAuthenticationFailureCode code,
            Throwable cause) {
        return new ProviderAuthenticationException(code, cause);
    }

    @Override
    @PreDestroy
    public synchronized void close() {
        if (poolHolder != null) {
            poolHolder.pool().close();
            poolHolder = null;
        }
    }

    private enum FailurePhase {
        SERVICE_BIND,
        SEARCH,
        USER_BIND
    }

    private record PoolHolder(
            SingleServerSet serverSet,
            LDAPConnectionPool pool,
            PostConnectProcessor postConnectProcessor
    ) {
    }

    @FunctionalInterface
    interface TlsSocketFactorySource {

        SSLSocketFactory create() throws GeneralSecurityException;
    }
}
