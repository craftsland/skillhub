package com.iflytek.skillhub.auth.identity;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Startup projection for the transitional static provider registry.
 *
 * <p>Startup reconciliation performs the authority compare-and-set. Every
 * catalog read then filters the configured descriptor snapshot against the
 * current persisted state, so mismatch and recovery changes made by another
 * application instance are visible without a process restart.
 */
@Component
class ReconciledIdentityProviderCatalog
        implements IdentityProviderCatalog, ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(
            ReconciledIdentityProviderCatalog.class);

    private final TrustedProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;
    private final AtomicReference<List<ProviderDescriptor>>
            configuredProviders = new AtomicReference<>(List.of());

    ReconciledIdentityProviderCatalog(
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
    }

    @Override
    public void run(ApplicationArguments args) {
        reconcile();
    }

    synchronized void reconcile() {
        List<ProviderDescriptor> descriptors;
        try {
            descriptors = List.copyOf(
                    descriptorSource.enabledDescriptors());
        } catch (RuntimeException exception) {
            configuredProviders.set(List.of());
            log.error(
                    "Identity provider descriptor reconciliation failed",
                    exception);
            return;
        }
        configuredProviders.set(descriptors);
        for (ProviderDescriptor descriptor : descriptors) {
            try {
                authorityLockService.requirePinnedAuthority(descriptor);
            } catch (IdentityCoreException exception) {
                log.warn(
                        "Identity provider '{}' is hidden after authority reconciliation: {}",
                        descriptor.providerCode(),
                        exception.getReasonCode());
            } catch (RuntimeException exception) {
                log.error(
                        "Identity provider '{}' is hidden because authority reconciliation failed",
                        descriptor.providerCode(),
                        exception);
            }
        }
    }

    @Override
    public List<IdentityProviderLoginMethod> listReadyProviders() {
        return configuredProviders.get().stream()
                .filter(this::isCurrentlyReady)
                .map(descriptor -> new IdentityProviderLoginMethod(
                        descriptor.providerCode(),
                        descriptor.displayName()))
                .toList();
    }

    private boolean isCurrentlyReady(ProviderDescriptor descriptor) {
        try {
            authorityLockService.requirePinnedAuthority(descriptor);
            return authorityLockService.isReady(descriptor);
        } catch (RuntimeException exception) {
            log.error(
                    "Identity provider '{}' is hidden because its persisted state cannot be read",
                    descriptor.providerCode(),
                    exception);
            return false;
        }
    }
}
