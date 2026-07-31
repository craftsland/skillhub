package com.iflytek.skillhub.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/**
 * Stable machine-readable error envelope for Identity Link operations.
 */
public record IdentityLinkErrorResponse(
        int code,
        String msg,
        @Schema(
                requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {
                        "INTENT_NOT_FOUND",
                        "REAUTHENTICATION_REQUIRED",
                        "SESSION_MISMATCH",
                        "INTENT_EXPIRED",
                        "ALREADY_CONSUMED",
                        "ACTIVE_INTENT_EXISTS",
                        "ACCOUNT_NOT_ELIGIBLE",
                        "PROVIDER_UNAVAILABLE",
                        "PROVIDER_AUTHENTICATION_FAILED",
                        "ALREADY_LINKED",
                        "IDENTITY_IN_USE",
                        "FINAL_LOGIN_METHOD",
                        "INVALID_OPERATION"
                })
        String reasonCode,
        Instant timestamp,
        String requestId
) {
}
