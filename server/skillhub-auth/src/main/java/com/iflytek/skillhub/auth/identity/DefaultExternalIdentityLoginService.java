package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import java.sql.SQLException;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

@Service
class DefaultExternalIdentityLoginService
        implements ExternalIdentityLoginService {

    private static final Logger log = LoggerFactory.getLogger(
            DefaultExternalIdentityLoginService.class);

    private final TrustedProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;
    private final IdentityAssertionFactory assertionFactory;
    private final IdentityResolutionTransaction resolutionTransaction;
    private final IdentityLoginMetrics metrics;
    private final IdentitySecurityAuditWriter securityAuditWriter;

    DefaultExternalIdentityLoginService(
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService,
            IdentityAssertionFactory assertionFactory,
            IdentityResolutionTransaction resolutionTransaction,
            IdentityLoginMetrics metrics,
            IdentitySecurityAuditWriter securityAuditWriter) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
        this.assertionFactory = assertionFactory;
        this.resolutionTransaction = resolutionTransaction;
        this.metrics = metrics;
        this.securityAuditWriter = securityAuditWriter;
    }

    @Override
    public IdentityLoginOutcome authenticate(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(context, "context");

        String metricProvider = "unresolved";
        String metricProtocol = "unresolved";
        try {
            ProviderDescriptor descriptor =
                    descriptorSource.require(provider);
            metricProvider = descriptor.providerCode();
            metricProtocol = descriptor.protocol();
            authorityLockService.requirePinnedAuthority(descriptor);
            IdentityAssertion assertion =
                    assertionFactory.create(descriptor, result);
            IdentityLoginOutcome outcome = resolveWithRetry(
                    assertion,
                    descriptor,
                    context);
            metrics.recordOutcome(
                    descriptor.providerCode(),
                    descriptor.protocol(),
                    outcome);
            return outcome;
        } catch (IdentityCoreException exception) {
            metrics.recordFailure(
                    metricProvider,
                    metricProtocol,
                    exception.getReasonCode());
            recordDeniedAudit(
                    metricProvider,
                    metricProtocol,
                    exception.getReasonCode(),
                    context);
            throw exception;
        } catch (RuntimeException exception) {
            metrics.recordSystemError(
                    metricProvider,
                    metricProtocol);
            throw exception;
        }
    }

    @Override
    public void recordProviderAuthenticationFailure(
            ResolvedProviderHandle provider,
            ProviderAuthenticationFailureCode failureCode,
            IdentityLoginContext context) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(failureCode, "failureCode");
        Objects.requireNonNull(context, "context");

        String providerCode = provider.providerCode();
        String protocol = "unknown";
        try {
            ProviderDescriptor descriptor = descriptorSource.require(provider);
            providerCode = descriptor.providerCode();
            protocol = descriptor.protocol();
        } catch (RuntimeException descriptorFailure) {
            log.warn(
                    "Unable to resolve provider descriptor for denial audit '{}'",
                    providerCode);
        }
        try {
            securityAuditWriter.recordProviderDenied(
                    providerCode,
                    protocol,
                    failureCode,
                    context);
        } catch (RuntimeException auditFailure) {
            log.error(
                    "Provider denial audit failed for provider '{}' and reason '{}'",
                    providerCode,
                    failureCode,
                    auditFailure);
        }
    }

    private void recordDeniedAudit(
            String providerCode,
            String protocol,
            IdentityFailureCode failureCode,
            IdentityLoginContext context) {
        try {
            securityAuditWriter.recordDenied(
                    providerCode,
                    protocol,
                    failureCode,
                    context);
        } catch (RuntimeException auditFailure) {
            log.error(
                    "Identity denial audit failed for provider '{}' and reason '{}'",
                    providerCode,
                    failureCode,
                    auditFailure);
        }
    }

    private IdentityLoginOutcome resolveWithRetry(
            IdentityAssertion assertion,
            ProviderDescriptor descriptor,
            IdentityLoginContext context) {
        try {
            return resolutionTransaction.resolve(
                    assertion,
                    descriptor,
                    context);
        } catch (DataIntegrityViolationException firstConflict) {
            if (!isUniqueConstraintViolation(firstConflict)) {
                throw firstConflict;
            }
            try {
                return resolutionTransaction.resolve(
                        assertion,
                        descriptor,
                        context);
            } catch (DataIntegrityViolationException repeatedConflict) {
                if (!isUniqueConstraintViolation(repeatedConflict)) {
                    repeatedConflict.addSuppressed(firstConflict);
                    throw repeatedConflict;
                }
                repeatedConflict.addSuppressed(firstConflict);
                throw new IdentityCoreException(
                        IdentityFailureCode.IDENTITY_IDENTIFIER_CONFLICT,
                        repeatedConflict);
            }
        }
    }

    private boolean isUniqueConstraintViolation(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof SQLException sqlException
                    && "23505".equals(sqlException.getSQLState())) {
                return true;
            }
            Throwable cause = current.getCause();
            if (cause == current) {
                break;
            }
            current = cause;
        }
        return false;
    }

}
