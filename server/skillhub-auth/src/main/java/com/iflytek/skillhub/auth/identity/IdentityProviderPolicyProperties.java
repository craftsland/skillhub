package com.iflytek.skillhub.auth.identity;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "skillhub.auth.identity")
class IdentityProviderPolicyProperties {

    private Map<String, ProviderPolicy> providers =
            new LinkedHashMap<>();

    ProviderIdentityPolicy resolve(String providerCode) {
        ProviderPolicy configured = providers.get(providerCode);
        if (configured == null) {
            return ProviderIdentityPolicy.defaults();
        }
        return new ProviderIdentityPolicy(
                configured.getProvisioningMode(),
                new ProfileSyncPolicy(
                        configured.getProfileSync().getDisplayName(),
                        configured.getProfileSync().getEmail(),
                        configured.getProfileSync().getAvatarUrl()));
    }

    public Map<String, ProviderPolicy> getProviders() {
        return providers;
    }

    public void setProviders(Map<String, ProviderPolicy> providers) {
        this.providers = providers == null
                ? new LinkedHashMap<>()
                : new LinkedHashMap<>(providers);
    }

    static final class ProviderPolicy {

        private ProvisioningMode provisioningMode =
                ProvisioningMode.AUTO;
        private ProfilePolicy profileSync = new ProfilePolicy();

        public ProvisioningMode getProvisioningMode() {
            return provisioningMode;
        }

        public void setProvisioningMode(
                ProvisioningMode provisioningMode) {
            this.provisioningMode = provisioningMode;
        }

        public ProfilePolicy getProfileSync() {
            return profileSync;
        }

        public void setProfileSync(ProfilePolicy profileSync) {
            this.profileSync = profileSync == null
                    ? new ProfilePolicy()
                    : profileSync;
        }
    }

    static final class ProfilePolicy {

        private ProfileSyncMode displayName =
                ProfileSyncMode.PRESERVE_LOCAL;
        private ProfileSyncMode email =
                ProfileSyncMode.FILL_IF_EMPTY;
        private ProfileSyncMode avatarUrl =
                ProfileSyncMode.PRESERVE_LOCAL;

        public ProfileSyncMode getDisplayName() {
            return displayName;
        }

        public void setDisplayName(ProfileSyncMode displayName) {
            this.displayName = displayName;
        }

        public ProfileSyncMode getEmail() {
            return email;
        }

        public void setEmail(ProfileSyncMode email) {
            this.email = email;
        }

        public ProfileSyncMode getAvatarUrl() {
            return avatarUrl;
        }

        public void setAvatarUrl(ProfileSyncMode avatarUrl) {
            this.avatarUrl = avatarUrl;
        }
    }

    record ProviderIdentityPolicy(
            ProvisioningMode provisioningMode,
            ProfileSyncPolicy profileSyncPolicy
    ) {
        ProviderIdentityPolicy {
            if (provisioningMode == null) {
                throw new IllegalArgumentException(
                        "Provisioning mode is required");
            }
            if (profileSyncPolicy == null) {
                throw new IllegalArgumentException(
                        "Profile sync policy is required");
            }
        }

        static ProviderIdentityPolicy defaults() {
            return new ProviderIdentityPolicy(
                    ProvisioningMode.AUTO,
                    ProfileSyncPolicy.defaults());
        }
    }
}
