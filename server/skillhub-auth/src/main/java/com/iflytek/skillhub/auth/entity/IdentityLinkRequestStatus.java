package com.iflytek.skillhub.auth.entity;

public enum IdentityLinkRequestStatus {
    PENDING_REAUTHENTICATION,
    READY,
    COMPLETED,
    EXPIRED,
    CANCELLED;

    public boolean isActive() {
        return this == PENDING_REAUTHENTICATION || this == READY;
    }
}
