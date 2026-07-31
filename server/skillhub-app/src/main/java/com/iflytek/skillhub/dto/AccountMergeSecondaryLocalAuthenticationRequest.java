package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AccountMergeSecondaryLocalAuthenticationRequest(
        @NotBlank(
                message =
                        "{validation.auth.accountMerge.username.notBlank}")
        @Size(
                max = 64,
                message =
                        "{validation.auth.accountMerge.username.size}")
        String username,
        @NotBlank(
                message =
                        "{validation.auth.accountMerge.password.notBlank}")
        String password
) {
}
