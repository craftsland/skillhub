package com.iflytek.skillhub.dto;

public record AccountMergeBrowserStartResponse(
        String actionUrl
) {
    public AccountMergeBrowserStartResponse {
        if (actionUrl == null
                || actionUrl.isBlank()
                || !actionUrl.startsWith("/")) {
            throw new IllegalArgumentException(
                    "Invalid account merge action URL");
        }
    }
}
