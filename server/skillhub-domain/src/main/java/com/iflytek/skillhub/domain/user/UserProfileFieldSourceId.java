package com.iflytek.skillhub.domain.user;

import java.io.Serializable;
import java.util.Objects;

public class UserProfileFieldSourceId implements Serializable {

    private String userId;
    private String fieldName;

    public UserProfileFieldSourceId() {
    }

    public UserProfileFieldSourceId(String userId, String fieldName) {
        this.userId = userId;
        this.fieldName = fieldName;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof UserProfileFieldSourceId that)) {
            return false;
        }
        return Objects.equals(userId, that.userId)
                && Objects.equals(fieldName, that.fieldName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, fieldName);
    }
}
