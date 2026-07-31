package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record CreateIdentityUnlinkRequest(
        @NotNull(message = "{validation.auth.identityLink.binding.required}")
        @Positive(message = "{validation.auth.identityLink.binding.positive}")
        Long bindingId
) {
}
