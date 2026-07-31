package com.iflytek.skillhub.auth.identity;

import java.util.Objects;
import org.springframework.stereotype.Service;

/**
 * Provider-bound implementation of {@link ExternalIdentityProofService}.
 */
@Service
class DefaultExternalIdentityProofService
        implements ExternalIdentityProofService {

    private final TrustedProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;
    private final IdentityAssertionFactory assertionFactory;
    private final IdentityResolutionTransaction resolutionTransaction;

    DefaultExternalIdentityProofService(
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService,
            IdentityAssertionFactory assertionFactory,
            IdentityResolutionTransaction resolutionTransaction) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
        this.assertionFactory = assertionFactory;
        this.resolutionTransaction = resolutionTransaction;
    }

    @Override
    public ExternalIdentityProof authenticateExisting(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(context, "context");
        ProviderDescriptor descriptor =
                descriptorSource.require(provider);
        authorityLockService.requirePinnedAuthority(descriptor);
        IdentityAssertion assertion =
                assertionFactory.create(descriptor, result);
        return resolutionTransaction
                .resolveExistingProof(
                        assertion,
                        descriptor,
                        context);
    }
}
