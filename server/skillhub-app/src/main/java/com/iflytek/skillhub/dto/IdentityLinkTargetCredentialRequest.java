package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotBlank;

public record IdentityLinkTargetCredentialRequest(
        @NotBlank(message = "{validation.auth.identityLink.username.notBlank}")
        String username,
        @NotBlank(message = "{validation.auth.identityLink.password.notBlank}")
        String password
) {
}
