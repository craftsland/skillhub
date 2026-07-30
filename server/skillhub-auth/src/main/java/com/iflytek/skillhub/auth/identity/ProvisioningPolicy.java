package com.iflytek.skillhub.auth.identity;

interface ProvisioningPolicy {

    ProvisioningMode evaluate(ProvisioningPolicyContext context);
}
