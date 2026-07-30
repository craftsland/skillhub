package com.iflytek.skillhub.auth.identity;

import java.util.List;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Server-owned static provider configuration consumed by the runtime registry.
 */
interface ConfiguredProviderDescriptorSource {

    List<ProviderDescriptor> configuredDescriptors();

    String resolveBrowserProviderCode(ClientRegistration registration);
}
