package com.iflytek.skillhub.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/**
 * Stable machine-readable error envelope for safe account merge.
 */
public record AccountMergeErrorResponse(
        int code,
        String msg,
        @Schema(
                requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {
                        "ACCOUNT_MERGE_UNAVAILABLE",
                        "MERGE_INTENT_NOT_FOUND",
                        "MERGE_REAUTH_REQUIRED",
                        "MERGE_PROVIDER_AUTHENTICATION_FAILED",
                        "MERGE_PROVIDER_UNAVAILABLE",
                        "MERGE_SESSION_MISMATCH",
                        "MERGE_PROOF_EXPIRED",
                        "MERGE_CONFLICT",
                        "MERGE_PREVIEW_STALE",
                        "MERGE_ALREADY_CONSUMED",
                        "MERGE_ACCOUNT_NOT_ELIGIBLE"
                })
        String reasonCode,
        Instant timestamp,
        String requestId
) {
}
