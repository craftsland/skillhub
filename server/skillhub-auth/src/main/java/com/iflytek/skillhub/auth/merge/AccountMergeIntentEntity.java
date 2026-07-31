package com.iflytek.skillhub.auth.merge;

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

/**
 * Persisted metadata for a server-side account-merge intent.
 *
 * <p>Raw proofs, passwords, provider tokens, and Session identifiers are never
 * persisted in this entity.
 */
@Entity
@Table(name = "account_merge_intent")
public class AccountMergeIntentEntity {

    private static final Pattern SHA256_PATTERN =
            Pattern.compile("[0-9a-f]{64}");

    @Id
    private UUID id;

    @Column(
            name = "primary_user_id",
            nullable = false,
            length = 128)
    private String primaryUserId;

    @Column(name = "secondary_user_id", length = 128)
    private String secondaryUserId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AccountMergeIntentStatus status;

    @Column(
            name = "primary_session_nonce_hash",
            nullable = false,
            length = 64)
    private String primarySessionNonceHash;

    @Column(
            name = "primary_proof_method",
            nullable = false,
            length = 96)
    private String primaryProofMethod;

    @Column(name = "primary_proof_at", nullable = false)
    private Instant primaryProofAt;

    @Column(name = "secondary_proof_method", length = 96)
    private String secondaryProofMethod;

    @Column(name = "secondary_proof_at")
    private Instant secondaryProofAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "preview_version")
    private Integer previewVersion;

    @Column(name = "preview_digest", length = 64)
    private String previewDigest;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Version
    @Column(name = "row_version", nullable = false)
    private long rowVersion;

    @Column(
            name = "created_at",
            nullable = false,
            updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AccountMergeIntentEntity() {
    }

    public AccountMergeIntentEntity(
            UUID id,
            String primaryUserId,
            String primarySessionNonceHash,
            String primaryProofMethod,
            Instant primaryProofAt,
            Instant expiresAt,
            Instant createdAt) {
        this.id = Objects.requireNonNull(id, "id");
        this.primaryUserId = requireText(
                primaryUserId,
                "primaryUserId",
                128);
        this.primarySessionNonceHash = requireHash(
                primarySessionNonceHash,
                "primarySessionNonceHash");
        this.primaryProofMethod = requireText(
                primaryProofMethod,
                "primaryProofMethod",
                96);
        this.primaryProofAt = Objects.requireNonNull(
                primaryProofAt,
                "primaryProofAt");
        this.expiresAt = Objects.requireNonNull(
                expiresAt,
                "expiresAt");
        this.createdAt = Objects.requireNonNull(
                createdAt,
                "createdAt");
        if (primaryProofAt.isAfter(createdAt)
                || !expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException(
                    "Invalid account merge intent time range");
        }
        this.status =
                AccountMergeIntentStatus
                        .PENDING_SECONDARY_PROOF;
        this.updatedAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public String getPrimaryUserId() {
        return primaryUserId;
    }

    public String getSecondaryUserId() {
        return secondaryUserId;
    }

    public AccountMergeIntentStatus getStatus() {
        return status;
    }

    public String getPrimarySessionNonceHash() {
        return primarySessionNonceHash;
    }

    public String getPrimaryProofMethod() {
        return primaryProofMethod;
    }

    public Instant getPrimaryProofAt() {
        return primaryProofAt;
    }

    public String getSecondaryProofMethod() {
        return secondaryProofMethod;
    }

    public Instant getSecondaryProofAt() {
        return secondaryProofAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Integer getPreviewVersion() {
        return previewVersion;
    }

    public String getPreviewDigest() {
        return previewDigest;
    }

    public Instant getConfirmedAt() {
        return confirmedAt;
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
        return !Objects.requireNonNull(now, "now")
                .isBefore(expiresAt);
    }

    public void expire(Instant now) {
        if (!status.isActive()) {
            throw new IllegalStateException(
                    "Only an active account merge intent can expire");
        }
        status = AccountMergeIntentStatus.EXPIRED;
        updatedAt = Objects.requireNonNull(now, "now");
    }

    public void recordSecondaryProof(
            String userId,
            String method,
            Instant now) {
        if (status
                != AccountMergeIntentStatus
                        .PENDING_SECONDARY_PROOF) {
            throw new IllegalStateException(
                    "Account merge intent is not waiting"
                            + " for a secondary proof");
        }
        String requiredUserId = requireText(
                userId,
                "secondaryUserId",
                128);
        if (requiredUserId.equals(primaryUserId)) {
            throw new IllegalArgumentException(
                    "Account merge users must be distinct");
        }
        secondaryUserId = requiredUserId;
        secondaryProofMethod = requireText(
                method,
                "secondaryProofMethod",
                96);
        secondaryProofAt = Objects.requireNonNull(now, "now");
        status =
                AccountMergeIntentStatus
                        .READY_FOR_PREVIEW;
        updatedAt = now;
    }

    public int recordPreview(
            String digest,
            boolean confirmable,
            Instant now) {
        if (status != AccountMergeIntentStatus.READY_FOR_PREVIEW
                && status
                        != AccountMergeIntentStatus.READY_TO_CONFIRM
                && status
                        != AccountMergeIntentStatus.FAILED_CONFLICT) {
            throw new IllegalStateException(
                    "Account merge intent is not ready"
                            + " for a preview");
        }
        previewVersion = previewVersion == null
                ? 1
                : Math.addExact(previewVersion, 1);
        previewDigest = requireHash(
                digest,
                "previewDigest");
        status = confirmable
                ? AccountMergeIntentStatus.READY_TO_CONFIRM
                : AccountMergeIntentStatus.FAILED_CONFLICT;
        updatedAt = Objects.requireNonNull(now, "now");
        return previewVersion;
    }

    public void markPreviewStale(Instant now) {
        if (status
                != AccountMergeIntentStatus.READY_TO_CONFIRM) {
            throw new IllegalStateException(
                    "Account merge intent has no confirmable preview");
        }
        status = AccountMergeIntentStatus.READY_FOR_PREVIEW;
        previewVersion = null;
        previewDigest = null;
        confirmedAt = null;
        updatedAt = Objects.requireNonNull(now, "now");
    }

    public void complete(Instant now) {
        if (status
                != AccountMergeIntentStatus.READY_TO_CONFIRM) {
            throw new IllegalStateException(
                    "Account merge intent is not ready"
                            + " to complete");
        }
        confirmedAt = Objects.requireNonNull(now, "now");
        completedAt = now;
        status = AccountMergeIntentStatus.COMPLETED;
        updatedAt = now;
    }

    public void cancel(Instant now) {
        if (!status.isActive()) {
            throw new IllegalStateException(
                    "Only an active account merge intent"
                            + " can be cancelled");
        }
        cancelledAt = Objects.requireNonNull(now, "now");
        status = AccountMergeIntentStatus.CANCELLED;
        updatedAt = now;
    }

    private static String requireHash(
            String value,
            String fieldName) {
        if (value == null
                || !SHA256_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "Invalid account merge " + fieldName);
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
                    "Invalid account merge " + fieldName);
        }
        return value;
    }
}
