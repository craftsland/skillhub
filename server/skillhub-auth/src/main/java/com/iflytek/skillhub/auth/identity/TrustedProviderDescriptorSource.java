package com.iflytek.skillhub.auth.identity;

import java.util.List;

interface TrustedProviderDescriptorSource {

    ProviderDescriptor require(ResolvedProviderHandle provider);

    List<ProviderDescriptor> enabledDescriptors();
}
