package com.iflytek.skillhub.auth.identity;

import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

/**
 * Core-owned Identity Link facade. Protocol adapters can only provide verified
 * external facts; trusted provider identity and assertion construction remain
 * inside the identity core.
 */
@Service
class DefaultExternalIdentityLinkService
        implements ExternalIdentityLinkService {

    private static final Logger log = LoggerFactory.getLogger(
            DefaultExternalIdentityLinkService.class);

    private final TrustedProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;
    private final IdentityAssertionFactory assertionFactory;
    private final IdentityLinkTransaction transaction;

    DefaultExternalIdentityLinkService(
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService,
            IdentityAssertionFactory assertionFactory,
            IdentityLinkTransaction transaction) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
        this.assertionFactory = assertionFactory;
        this.transaction = transaction;
    }

    @Override
    public IdentityLinkOutcome reauthenticate(
            IdentityLinkActor actor,
            UUID intentId,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result) {
        PreparedAssertion prepared = prepare(provider, result);
        return new IdentityLinkOutcome.Reauthenticated(
                transaction.markExternalReauthenticated(
                        actor,
                        intentId,
                        prepared.assertion(),
                        prepared.descriptor()));
    }

    @Override
    public IdentityLinkOutcome link(
            IdentityLinkActor actor,
            UUID intentId,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result) {
        PreparedAssertion prepared = prepare(provider, result);
        try {
            IdentityLinkTransaction.LinkedBinding linked =
                    transaction.link(
                            actor,
                            intentId,
                            prepared.assertion(),
                            prepared.descriptor());
            return new IdentityLinkOutcome.Linked(
                    linked.principal(),
                    linked.bindingId());
        } catch (DataIntegrityViolationException exception) {
            if (isUniqueConstraintViolation(exception)) {
                recordIdentityInUseDenial(actor, intentId);
                throw new IdentityLinkException(
                        IdentityLinkFailureCode.IDENTITY_IN_USE,
                        exception);
            }
            throw exception;
        }
    }

    private void recordIdentityInUseDenial(
            IdentityLinkActor actor,
            UUID intentId) {
        try {
            transaction.recordRejectedAfterRollback(
                    actor,
                    intentId,
                    IdentityLinkFailureCode.IDENTITY_IN_USE);
        } catch (RuntimeException auditFailure) {
            log.error(
                    "Identity Link denial audit failed for intent '{}' and reason '{}'",
                    intentId,
                    IdentityLinkFailureCode.IDENTITY_IN_USE,
                    auditFailure);
        }
    }

    private PreparedAssertion prepare(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(result, "result");
        ProviderDescriptor descriptor =
                descriptorSource.require(provider);
        authorityLockService.requirePinnedAuthority(descriptor);
        return new PreparedAssertion(
                descriptor,
                assertionFactory.create(descriptor, result));
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

    private record PreparedAssertion(
            ProviderDescriptor descriptor,
            IdentityAssertion assertion) {
    }
}
