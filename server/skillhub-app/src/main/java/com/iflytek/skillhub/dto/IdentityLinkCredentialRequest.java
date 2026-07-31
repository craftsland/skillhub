package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record IdentityLinkCredentialRequest(
        @NotBlank(message = "{validation.auth.identityLink.provider.notBlank}")
        @Size(
                max = 64,
                message = "{validation.auth.identityLink.provider.size}")
        @Pattern(
                regexp = "[a-z0-9][a-z0-9._-]{0,63}",
                message = "{validation.auth.identityLink.provider.invalid}")
        String providerCode,
        @NotBlank(message = "{validation.auth.identityLink.username.notBlank}")
        String username,
        @NotBlank(message = "{validation.auth.identityLink.password.notBlank}")
        String password
) {
}
