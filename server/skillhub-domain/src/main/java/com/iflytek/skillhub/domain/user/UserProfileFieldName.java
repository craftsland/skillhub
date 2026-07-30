package com.iflytek.skillhub.domain.user;

public enum UserProfileFieldName {
    DISPLAY_NAME("displayName"),
    EMAIL("email"),
    AVATAR_URL("avatarUrl");

    private final String databaseValue;

    UserProfileFieldName(String databaseValue) {
        this.databaseValue = databaseValue;
    }

    public String databaseValue() {
        return databaseValue;
    }
}
