package com.iflytek.skillhub.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

@Entity
@Table(name = "identity_link_request")
public class IdentityLinkRequest {

    private static final Pattern STATE_HASH_PATTERN =
            Pattern.compile("[0-9a-f]{64}");

    @Id
    private UUID id;

    @Column(name = "primary_user_id", nullable = false, length = 128)
    private String primaryUserId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private IdentityLinkOperation operation;

    @Column(name = "provider_code", nullable = false, length = 64)
    private String providerCode;

    @Column(name = "target_binding_id")
    private Long targetBindingId;

    @Column(name = "state_hash", nullable = false, length = 64)
    private String stateHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private IdentityLinkRequestStatus status;

    @Column(name = "reauthentication_method", length = 96)
    private String reauthenticationMethod;

    @Column(name = "reauthenticated_at")
    private Instant reauthenticatedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Version
    @Column(name = "row_version", nullable = false)
    private long rowVersion;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected IdentityLinkRequest() {
    }

    public IdentityLinkRequest(
            UUID id,
            String primaryUserId,
            IdentityLinkOperation operation,
            String providerCode,
            Long targetBindingId,
            String stateHash,
            Instant expiresAt,
            Instant createdAt) {
        this.id = Objects.requireNonNull(id, "id");
        this.primaryUserId = requireText(primaryUserId, "primaryUserId", 128);
        this.operation = Objects.requireNonNull(operation, "operation");
        this.providerCode = requireText(providerCode, "providerCode", 64);
        this.targetBindingId = targetBindingId;
        this.stateHash = requireStateHash(stateHash);
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException(
                    "Identity link request expiry must be in the future");
        }
        if ((operation == IdentityLinkOperation.LINK && targetBindingId != null)
                || (operation == IdentityLinkOperation.UNLINK
                && targetBindingId == null)) {
            throw new IllegalArgumentException(
                    "Identity link request target does not match operation");
        }
        this.status = IdentityLinkRequestStatus.PENDING_REAUTHENTICATION;
        this.updatedAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public String getPrimaryUserId() {
        return primaryUserId;
    }

    public IdentityLinkOperation getOperation() {
        return operation;
    }

    public String getProviderCode() {
        return providerCode;
    }

    public Long getTargetBindingId() {
        return targetBindingId;
    }

    public String getStateHash() {
        return stateHash;
    }

    public IdentityLinkRequestStatus getStatus() {
        return status;
    }

    public String getReauthenticationMethod() {
        return reauthenticationMethod;
    }

    public Instant getReauthenticatedAt() {
        return reauthenticatedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public Instant getCancelledAt() {
        return cancelledAt;
    }

    public long getRowVersion() {
        return rowVersion;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public void markReauthenticated(String method, Instant now) {
        requireStatus(IdentityLinkRequestStatus.PENDING_REAUTHENTICATION);
        reauthenticationMethod = requireText(
                method,
                "reauthenticationMethod",
                96);
        reauthenticatedAt = Objects.requireNonNull(now, "now");
        status = IdentityLinkRequestStatus.READY;
        updatedAt = now;
    }

    public void complete(Instant now) {
        requireStatus(IdentityLinkRequestStatus.READY);
        completedAt = Objects.requireNonNull(now, "now");
        status = IdentityLinkRequestStatus.COMPLETED;
        updatedAt = now;
    }

    public void expire(Instant now) {
        if (!status.isActive()) {
            throw new IllegalStateException(
                    "Only an active identity link request can expire");
        }
        status = IdentityLinkRequestStatus.EXPIRED;
        updatedAt = Objects.requireNonNull(now, "now");
    }

    public void cancel(Instant now) {
        if (!status.isActive()) {
            throw new IllegalStateException(
                    "Only an active identity link request can be cancelled");
        }
        cancelledAt = Objects.requireNonNull(now, "now");
        status = IdentityLinkRequestStatus.CANCELLED;
        updatedAt = now;
    }

    private void requireStatus(IdentityLinkRequestStatus required) {
        if (status != required) {
            throw new IllegalStateException(
                    "Identity link request is not in state " + required);
        }
    }

    private static String requireStateHash(String value) {
        if (value == null || !STATE_HASH_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "Invalid identity link state hash");
        }
        return value;
    }

    private static String requireText(
            String value,
            String fieldName,
            int maximumLength) {
        if (value == null
                || value.isBlank()
                || value.length() > maximumLength) {
            throw new IllegalArgumentException(
                    "Invalid identity link " + fieldName);
        }
        return value;
    }
}
