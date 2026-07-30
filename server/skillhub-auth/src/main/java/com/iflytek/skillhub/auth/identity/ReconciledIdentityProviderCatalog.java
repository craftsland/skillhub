package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.provider.CredentialAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.PassiveAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.ProviderInstanceDefinition;
import com.iflytek.skillhub.auth.provider.SubjectNormalization;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;

/**
 * Runtime provider registry assembled from trusted static browser
 * configuration and built-in credential/passive adapters.
 *
 * <p>Startup reconciliation performs the authority compare-and-set. Every
 * catalog read then filters the configured descriptor snapshot against the
 * current persisted state, so mismatch and recovery changes made by another
 * application instance are visible without a process restart.
 */
@Component
class ReconciledIdentityProviderCatalog
        implements IdentityProviderRegistry,
        TrustedProviderDescriptorSource,
        TrustedProviderRouteResolver,
        ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(
            ReconciledIdentityProviderCatalog.class);

    private final ConfiguredProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;
    private final IdentityBindingPreflightService bindingPreflightService;
    private final IdentityProviderPolicyProperties policyProperties;
    private final List<CredentialAuthenticationAdapter> credentialAdapters;
    private final List<PassiveAuthenticationAdapter> passiveAdapters;
    private final AtomicReference<RegistrySnapshot> snapshot =
            new AtomicReference<>(RegistrySnapshot.empty());

    ReconciledIdentityProviderCatalog(
            ConfiguredProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService,
            IdentityBindingPreflightService bindingPreflightService,
            IdentityProviderPolicyProperties policyProperties,
            List<CredentialAuthenticationAdapter> credentialAdapters,
            List<PassiveAuthenticationAdapter> passiveAdapters) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
        this.bindingPreflightService = bindingPreflightService;
        this.policyProperties = policyProperties;
        this.credentialAdapters = List.copyOf(credentialAdapters);
        this.passiveAdapters = List.copyOf(passiveAdapters);
    }

    @Override
    public void run(ApplicationArguments args) {
        reconcile();
    }

    synchronized void reconcile() {
        RegistrySnapshot reconciled = assembleSnapshot();
        snapshot.set(reconciled);
        List<ProviderDescriptor> descriptors = reconciled.descriptors()
                .values()
                .stream()
                .sorted(Comparator.comparing(
                        ProviderDescriptor::providerCode))
                .toList();
        reportUnconfiguredBindingProviders(descriptors);
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

    private RegistrySnapshot assembleSnapshot() {
        Map<String, ProviderDescriptor> descriptors =
                new LinkedHashMap<>();
        Set<String> browserProviders = new HashSet<>();
        Map<String, CredentialRegistration> credentials =
                new LinkedHashMap<>();
        Map<String, PassiveRegistration> passives =
                new LinkedHashMap<>();
        Set<String> invalidProviders = new HashSet<>();

        try {
            for (ProviderDescriptor descriptor
                    : descriptorSource.configuredDescriptors()) {
                registerDescriptor(
                        descriptors,
                        invalidProviders,
                        descriptor);
                browserProviders.add(descriptor.providerCode());
            }
        } catch (RuntimeException exception) {
            log.error(
                    "Configured browser provider discovery failed");
            log.debug(
                    "Configured browser provider discovery failure type: {}",
                    exception.getClass().getSimpleName());
        }

        for (CredentialAuthenticationAdapter adapter
                : credentialAdapters) {
            try {
                ProviderInstanceDefinition definition =
                        adapter.provider();
                if (!definition.enabled()) {
                    continue;
                }
                ProviderDescriptor descriptor =
                        descriptorFrom(definition);
                registerDescriptor(
                        descriptors,
                        invalidProviders,
                        descriptor);
                CredentialRegistration previous = credentials.putIfAbsent(
                        descriptor.providerCode(),
                        new CredentialRegistration(
                                adapter,
                                definition.displayName()));
                if (previous != null) {
                    invalidProviders.add(descriptor.providerCode());
                }
            } catch (RuntimeException exception) {
                log.warn(
                        "Credential provider adapter is hidden because its trusted definition is invalid");
                log.debug(
                        "Credential provider definition failure type: {}",
                        exception.getClass().getSimpleName());
            }
        }

        for (PassiveAuthenticationAdapter adapter : passiveAdapters) {
            try {
                ProviderInstanceDefinition definition =
                        adapter.provider();
                if (!definition.enabled()) {
                    continue;
                }
                ProviderDescriptor descriptor =
                        descriptorFrom(definition);
                registerDescriptor(
                        descriptors,
                        invalidProviders,
                        descriptor);
                PassiveRegistration previous = passives.putIfAbsent(
                        descriptor.providerCode(),
                        new PassiveRegistration(
                                adapter,
                                definition.displayName()));
                if (previous != null) {
                    invalidProviders.add(descriptor.providerCode());
                }
            } catch (RuntimeException exception) {
                log.warn(
                        "Passive provider adapter is hidden because its trusted definition is invalid");
                log.debug(
                        "Passive provider definition failure type: {}",
                        exception.getClass().getSimpleName());
            }
        }

        for (String providerCode : invalidProviders) {
            descriptors.remove(providerCode);
            browserProviders.remove(providerCode);
            credentials.remove(providerCode);
            passives.remove(providerCode);
            log.error(
                    "Identity provider '{}' is hidden because trusted definitions or capabilities conflict",
                    providerCode);
        }

        return new RegistrySnapshot(
                Map.copyOf(descriptors),
                Set.copyOf(browserProviders),
                Map.copyOf(credentials),
                Map.copyOf(passives));
    }

    private void registerDescriptor(
            Map<String, ProviderDescriptor> descriptors,
            Set<String> invalidProviders,
            ProviderDescriptor descriptor) {
        ProviderDescriptor existing = descriptors.putIfAbsent(
                descriptor.providerCode(),
                descriptor);
        if (existing != null && !existing.equals(descriptor)) {
            invalidProviders.add(descriptor.providerCode());
        }
    }

    private ProviderDescriptor descriptorFrom(
            ProviderInstanceDefinition definition) {
        Map<String, SubjectCanonicalizer> canonicalizers =
                new LinkedHashMap<>();
        definition.subjectNormalizations().forEach(
                (subjectType, normalization) ->
                        canonicalizers.put(
                                subjectType,
                                canonicalizer(normalization)));
        IdentityProviderPolicyProperties.ProviderIdentityPolicy policy =
                policyProperties.resolve(definition.providerCode());
        return new ProviderDescriptor(
                definition.providerCode(),
                definition.protocol(),
                definition.canonicalAuthority(),
                definition.displayName(),
                definition.primarySubjectType(),
                definition.legacyPrimarySubjectType(),
                canonicalizers,
                definition.displayNameAttributes(),
                definition.emailAttributes(),
                definition.avatarAttributes(),
                definition.emailAssuranceLimit(),
                policy.provisioningMode(),
                policy.profileSyncPolicy());
    }

    private SubjectCanonicalizer canonicalizer(
            SubjectNormalization normalization) {
        return switch (normalization) {
            case EXACT -> SubjectCanonicalizer.EXACT;
            case DECIMAL -> SubjectCanonicalizer.DECIMAL;
        };
    }

    private void reportUnconfiguredBindingProviders(
            List<ProviderDescriptor> descriptors) {
        try {
            List<String> unconfiguredProviders = bindingPreflightService
                    .findProvidersWithoutTrustedDescriptor(descriptors);
            if (!unconfiguredProviders.isEmpty()) {
                log.error(
                        "Identity binding preflight found provider codes without a trusted descriptor: {}",
                        unconfiguredProviders);
            }
        } catch (RuntimeException exception) {
            log.error(
                    "Identity binding provider preflight failed",
                    exception);
        }
    }

    @Override
    public List<IdentityProviderLoginMethod> listReadyProviders() {
        RegistrySnapshot current = snapshot.get();
        return current.descriptors().values().stream()
                .sorted(Comparator.comparing(
                        ProviderDescriptor::providerCode))
                .filter(descriptor -> current.browserProviders()
                        .contains(descriptor.providerCode()))
                .filter(this::isCurrentlyReady)
                .map(descriptor -> loginMethod(
                        descriptor.providerCode(),
                        descriptor.displayName(),
                        IdentityProviderLoginMethodType.OAUTH_REDIRECT))
                .toList();
    }

    @Override
    public List<IdentityProviderLoginMethod> listReadyLoginMethods() {
        RegistrySnapshot current = snapshot.get();
        List<IdentityProviderLoginMethod> methods = new ArrayList<>();
        List<ProviderDescriptor> descriptors = current.descriptors()
                .values()
                .stream()
                .sorted(Comparator.comparing(
                        ProviderDescriptor::providerCode))
                .toList();
        for (ProviderDescriptor descriptor : descriptors) {
            if (!isCurrentlyReady(descriptor)) {
                continue;
            }
            String providerCode = descriptor.providerCode();
            if (current.browserProviders().contains(providerCode)) {
                methods.add(loginMethod(
                        providerCode,
                        descriptor.displayName(),
                        IdentityProviderLoginMethodType.OAUTH_REDIRECT));
            }
            CredentialRegistration credential =
                    current.credentials().get(providerCode);
            if (credential != null) {
                methods.add(loginMethod(
                        providerCode,
                        credential.displayName(),
                        IdentityProviderLoginMethodType.DIRECT_PASSWORD));
            }
            PassiveRegistration passive =
                    current.passives().get(providerCode);
            if (passive != null) {
                methods.add(loginMethod(
                        providerCode,
                        passive.displayName(),
                        IdentityProviderLoginMethodType.SESSION_BOOTSTRAP));
            }
        }
        return List.copyOf(methods);
    }

    @Override
    public CredentialRoute requireCredentialRoute(
            String providerCode) {
        RegistrySnapshot current = snapshot.get();
        ProviderDescriptor descriptor =
                requireReadyDescriptor(current, providerCode);
        CredentialRegistration registration =
                current.credentials().get(providerCode);
        if (registration == null) {
            throw providerDisabled();
        }
        return new CredentialRoute(
                new DefaultResolvedProviderHandle(
                        descriptor.providerCode()),
                registration.adapter());
    }

    @Override
    public PassiveRoute requirePassiveRoute(String providerCode) {
        RegistrySnapshot current = snapshot.get();
        ProviderDescriptor descriptor =
                requireReadyDescriptor(current, providerCode);
        PassiveRegistration registration =
                current.passives().get(providerCode);
        if (registration == null) {
            throw providerDisabled();
        }
        return new PassiveRoute(
                new DefaultResolvedProviderHandle(
                        descriptor.providerCode()),
                registration.adapter());
    }

    @Override
    public ResolvedProviderHandle resolve(
            ClientRegistration registration) {
        String providerCode =
                descriptorSource.resolveBrowserProviderCode(registration);
        RegistrySnapshot current = snapshot.get();
        if (!current.browserProviders().contains(providerCode)) {
            throw providerDisabled();
        }
        ProviderDescriptor descriptor =
                requireReadyDescriptor(current, providerCode);
        return new DefaultResolvedProviderHandle(
                descriptor.providerCode());
    }

    @Override
    public ProviderDescriptor require(ResolvedProviderHandle provider) {
        if (!(provider instanceof DefaultResolvedProviderHandle handle)) {
            throw providerDisabled();
        }
        ProviderDescriptor descriptor = snapshot.get()
                .descriptors()
                .get(handle.providerCode());
        if (descriptor == null) {
            throw providerDisabled();
        }
        return descriptor;
    }

    @Override
    public List<ProviderDescriptor> enabledDescriptors() {
        return snapshot.get().descriptors().values().stream()
                .sorted(Comparator.comparing(
                        ProviderDescriptor::providerCode))
                .toList();
    }

    private ProviderDescriptor requireReadyDescriptor(
            RegistrySnapshot current,
            String providerCode) {
        if (providerCode == null) {
            throw providerDisabled();
        }
        ProviderDescriptor descriptor =
                current.descriptors().get(providerCode);
        if (descriptor == null) {
            throw providerDisabled();
        }
        authorityLockService.requirePinnedAuthority(descriptor);
        if (!authorityLockService.isReady(descriptor)) {
            throw providerDisabled();
        }
        return descriptor;
    }

    private IdentityProviderLoginMethod loginMethod(
            String providerCode,
            String displayName,
            IdentityProviderLoginMethodType methodType) {
        return new IdentityProviderLoginMethod(
                providerCode,
                displayName,
                methodType);
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

    private IdentityCoreException providerDisabled() {
        return new IdentityCoreException(
                IdentityFailureCode.PROVIDER_DISABLED);
    }

    private record CredentialRegistration(
            CredentialAuthenticationAdapter adapter,
            String displayName) {
    }

    private record PassiveRegistration(
            PassiveAuthenticationAdapter adapter,
            String displayName) {
    }

    private record RegistrySnapshot(
            Map<String, ProviderDescriptor> descriptors,
            Set<String> browserProviders,
            Map<String, CredentialRegistration> credentials,
            Map<String, PassiveRegistration> passives
    ) {
        private static RegistrySnapshot empty() {
            return new RegistrySnapshot(
                    Map.of(),
                    Set.of(),
                    Map.of(),
                    Map.of());
        }
    }
}
