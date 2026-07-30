package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.provider.CredentialAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.PassiveAuthenticationAdapter;
import java.util.List;
import java.util.Objects;

/**
 * Unified, fail-closed query and routing surface for configured identity
 * providers.
 */
public interface IdentityProviderRegistry extends IdentityProviderCatalog {

    List<IdentityProviderLoginMethod> listReadyLoginMethods();

    CredentialRoute requireCredentialRoute(String providerCode);

    PassiveRoute requirePassiveRoute(String providerCode);

    class CredentialRoute {
        private final ResolvedProviderHandle provider;
        private final CredentialAuthenticationAdapter adapter;

        public CredentialRoute(
                ResolvedProviderHandle provider,
                CredentialAuthenticationAdapter adapter) {
            this.provider = Objects.requireNonNull(
                    provider,
                    "provider");
            this.adapter = Objects.requireNonNull(
                    adapter,
                    "adapter");
        }

        public ResolvedProviderHandle provider() {
            return provider;
        }

        public CredentialAuthenticationAdapter adapter() {
            return adapter;
        }
    }

    class PassiveRoute {
        private final ResolvedProviderHandle provider;
        private final PassiveAuthenticationAdapter adapter;

        public PassiveRoute(
                ResolvedProviderHandle provider,
                PassiveAuthenticationAdapter adapter) {
            this.provider = Objects.requireNonNull(
                    provider,
                    "provider");
            this.adapter = Objects.requireNonNull(
                    adapter,
                    "adapter");
        }

        public ResolvedProviderHandle provider() {
            return provider;
        }

        public PassiveAuthenticationAdapter adapter() {
            return adapter;
        }
    }
}
