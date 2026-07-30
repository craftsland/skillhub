package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class IdentityBindingPreflightService {

    private final IdentityBindingRepository bindingRepository;

    IdentityBindingPreflightService(
            IdentityBindingRepository bindingRepository) {
        this.bindingRepository = bindingRepository;
    }

    @Transactional(readOnly = true)
    public List<String> findProvidersWithoutTrustedDescriptor(
            List<ProviderDescriptor> descriptors) {
        Set<String> trustedProviderCodes = descriptors.stream()
                .map(ProviderDescriptor::providerCode)
                .collect(Collectors.toUnmodifiableSet());
        return bindingRepository.findDistinctProviderCodes().stream()
                .filter(providerCode ->
                        !trustedProviderCodes.contains(providerCode))
                .sorted()
                .toList();
    }
}
