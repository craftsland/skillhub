package com.iflytek.skillhub.dto;

import java.time.Instant;

public record AccountMergePrimaryProofResponse(
        String method,
        Instant expiresAt
) {
}
