package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.policy.AccessDecision;
import com.iflytek.skillhub.auth.policy.AccessPolicy;
import com.iflytek.skillhub.auth.policy.IdentityAccessContext;
import com.iflytek.skillhub.domain.user.UserStatus;
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
    private final AccessPolicy accessPolicy;
    private final IdentityResolutionTransaction resolutionTransaction;

    DefaultExternalIdentityLoginService(
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService,
            IdentityAssertionFactory assertionFactory,
            AccessPolicy accessPolicy,
            IdentityResolutionTransaction resolutionTransaction) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
        this.assertionFactory = assertionFactory;
        this.accessPolicy = accessPolicy;
        this.resolutionTransaction = resolutionTransaction;
    }

    @Override
    public IdentityLoginOutcome authenticate(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(context, "context");

        ProviderDescriptor descriptor = descriptorSource.require(provider);
        authorityLockService.requirePinnedAuthority(descriptor);
        IdentityAssertion assertion =
                assertionFactory.create(descriptor, result);
        AccessDecision decision = accessPolicy.evaluate(
                toAccessContext(assertion, context));
        if (decision == AccessDecision.DENY) {
            throw new IdentityCoreException(
                    IdentityFailureCode.ACCESS_DENIED);
        }

        UserStatus initialStatus =
                decision == AccessDecision.PENDING_APPROVAL
                        ? UserStatus.PENDING
                        : UserStatus.ACTIVE;
        try {
            return resolutionTransaction.resolve(
                    assertion,
                    initialStatus,
                    descriptor.legacyPrimarySubjectType());
        } catch (DataIntegrityViolationException firstConflict) {
            if (!isUniqueConstraintViolation(firstConflict)) {
                throw firstConflict;
            }
            try {
                return resolutionTransaction.resolve(
                        assertion,
                        initialStatus,
                        descriptor.legacyPrimarySubjectType());
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

    private IdentityAccessContext toAccessContext(
            IdentityAssertion assertion,
            IdentityLoginContext context) {
        return new IdentityAccessContext(
                assertion.provider().providerCode(),
                assertion.primarySubject().type(),
                assertion.primarySubject().value(),
                assertion.profile().email().map(EmailClaim::value),
                assertion.profile().email()
                        .map(EmailClaim::assurance)
                        .orElse(EmailAssurance.UNVERIFIED),
                context);
    }
}
