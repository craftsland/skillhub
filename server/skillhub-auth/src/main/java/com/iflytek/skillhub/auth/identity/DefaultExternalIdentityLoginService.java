package com.iflytek.skillhub.auth.identity;

import java.sql.SQLException;
import java.util.Objects;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

@Service
class DefaultExternalIdentityLoginService
        implements ExternalIdentityLoginService {

    private final TrustedProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;
    private final IdentityAssertionFactory assertionFactory;
    private final IdentityResolutionTransaction resolutionTransaction;
    private final IdentityLoginMetrics metrics;

    DefaultExternalIdentityLoginService(
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService,
            IdentityAssertionFactory assertionFactory,
            IdentityResolutionTransaction resolutionTransaction,
            IdentityLoginMetrics metrics) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
        this.assertionFactory = assertionFactory;
        this.resolutionTransaction = resolutionTransaction;
        this.metrics = metrics;
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
        try {
            ProviderDescriptor descriptor =
                    descriptorSource.require(provider);
            metricProvider = descriptor.providerCode();
            authorityLockService.requirePinnedAuthority(descriptor);
            IdentityAssertion assertion =
                    assertionFactory.create(descriptor, result);
            IdentityLoginOutcome outcome = resolveWithRetry(
                    assertion,
                    descriptor,
                    context);
            metrics.recordOutcome(
                    descriptor.providerCode(),
                    outcome);
            return outcome;
        } catch (IdentityCoreException exception) {
            metrics.recordFailure(
                    metricProvider,
                    exception.getReasonCode());
            throw exception;
        } catch (RuntimeException exception) {
            metrics.recordSystemError(metricProvider);
            throw exception;
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
