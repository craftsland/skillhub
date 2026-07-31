package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.Min;

public record AccountMergeConfirmRequest(
        @Min(1) int previewVersion
) {
}
