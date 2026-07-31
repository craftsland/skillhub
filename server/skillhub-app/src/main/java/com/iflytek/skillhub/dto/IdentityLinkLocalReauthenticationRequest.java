package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotBlank;

public record IdentityLinkLocalReauthenticationRequest(
        @NotBlank(message = "{validation.auth.identityLink.password.notBlank}")
        String password
) {
}
