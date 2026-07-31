package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotBlank;

public record AccountMergeLocalReauthenticationRequest(
        @NotBlank(
                message =
                        "{validation.auth.accountMerge.password.notBlank}")
        String password
) {
}
