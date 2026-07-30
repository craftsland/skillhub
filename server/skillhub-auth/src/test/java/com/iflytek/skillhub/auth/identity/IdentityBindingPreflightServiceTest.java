package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IdentityBindingPreflightServiceTest {

    @Test
    void reportsHistoricalProviderCodesWithoutTrustedDescriptors() {
        IdentityBindingRepository bindingRepository =
                mock(IdentityBindingRepository.class);
        when(bindingRepository.findDistinctProviderCodes())
                .thenReturn(List.of(
                        "removed-provider",
                        "github",
                        "ambiguous-provider"));
        IdentityBindingPreflightService service =
                new IdentityBindingPreflightService(
                        bindingRepository);

        assertThat(service.findProvidersWithoutTrustedDescriptor(
                List.of(descriptor("github"))))
                .containsExactly(
                        "ambiguous-provider",
                        "removed-provider");
    }

    private static ProviderDescriptor descriptor(String providerCode) {
        return new ProviderDescriptor(
                providerCode,
                "oidc",
                "https://" + providerCode + ".example",
                providerCode,
                "oidc_sub",
                "oidc_sub",
                Map.of(
                        "oidc_sub",
                        SubjectCanonicalizer.EXACT),
                List.of("name"),
                List.of("email"),
                List.of("picture"),
                EmailAssurance.VERIFIED);
    }
}
