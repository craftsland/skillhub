package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

record ProfileSyncPolicy(
        ProfileSyncMode displayName,
        ProfileSyncMode email,
        ProfileSyncMode avatarUrl
) {
    ProfileSyncPolicy {
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(avatarUrl, "avatarUrl");
    }

    static ProfileSyncPolicy defaults() {
        return new ProfileSyncPolicy(
                ProfileSyncMode.PRESERVE_LOCAL,
                ProfileSyncMode.FILL_IF_EMPTY,
                ProfileSyncMode.PRESERVE_LOCAL);
    }
}
