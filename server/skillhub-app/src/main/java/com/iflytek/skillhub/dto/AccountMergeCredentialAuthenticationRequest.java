package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AccountMergeCredentialAuthenticationRequest(
        @NotBlank
        @Size(max = 64)
        String providerCode,
        @NotBlank
        @Size(max = 320)
        String username,
        @NotBlank
        @Size(max = 1024)
        String password
) {
}
