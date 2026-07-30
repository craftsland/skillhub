package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
class DefaultIdentityProviderAuthorityOperations
        implements IdentityProviderAuthorityOperations {

    private final TrustedProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;

    DefaultIdentityProviderAuthorityOperations(
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService) {
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
    }

    @Override
    public IdentityProviderAuthorityRecoveryResult recoverSameAuthority(
            String providerCode,
            IdentityProviderAuthorityRecoveryContext context) {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(context, "context");
        ProviderDescriptor descriptor = descriptorSource
                .enabledDescriptors()
                .stream()
                .filter(candidate -> candidate.providerCode()
                        .equals(providerCode))
                .findFirst()
                .orElseThrow(() -> new AuthFlowException(
                        HttpStatus.NOT_FOUND,
                        "error.auth.provider.notFound"));

        SameAuthorityRecoveryEvaluation recovery =
                authorityLockService.recoverSameAuthority(
                        descriptor,
                        context);
        AuthorityLockEvaluation authority = recovery.authority();
        if (!authority.ready()) {
            String messageCode = authority.state()
                    == IdentityProviderStatus.AUTHORITY_MISMATCH
                    ? "error.auth.provider.authorityRecoveryMismatch"
                    : "error.auth.provider.authorityRecoveryUnavailable";
            throw new AuthFlowException(
                    HttpStatus.CONFLICT,
                    messageCode);
        }
        return new IdentityProviderAuthorityRecoveryResult(
                descriptor.providerCode(),
                recovery.recovered(),
                authority.state().name());
    }
}
