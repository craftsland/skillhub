package com.iflytek.skillhub.auth.identity;

import org.springframework.stereotype.Component;

@Component
class DescriptorProvisioningPolicy implements ProvisioningPolicy {

    @Override
    public ProvisioningMode evaluate(
            ProvisioningPolicyContext context) {
        return context.configuredMode();
    }
}
