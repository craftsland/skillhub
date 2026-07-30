package com.iflytek.skillhub.auth.entity;

import java.time.Clock;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "identity_binding_subject")
public class IdentityBindingSubject {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "binding_id", nullable = false)
    private Long bindingId;

    @Column(name = "provider_code", nullable = false, length = 64)
    private String providerCode;

    @Column(name = "subject_type", nullable = false, length = 64)
    private String subjectType;

    @Column(name = "subject_value", nullable = false, length = 512)
    private String subjectValue;

    @Column(name = "is_primary", nullable = false)
    private boolean primary;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private IdentityBindingSubjectStatus status =
            IdentityBindingSubjectStatus.ACTIVE;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected IdentityBindingSubject() {}

    public IdentityBindingSubject(
            Long bindingId,
            String providerCode,
            String subjectType,
            String subjectValue,
            boolean primary,
            Instant lastSeenAt) {
        this.bindingId = bindingId;
        this.providerCode = providerCode;
        this.subjectType = subjectType;
        this.subjectValue = subjectValue;
        this.primary = primary;
        this.status = IdentityBindingSubjectStatus.ACTIVE;
        this.lastSeenAt = lastSeenAt;
    }

    @PrePersist
    void prePersist() {
        createdAt = Instant.now(Clock.systemUTC());
    }

    public Long getId() { return id; }
    public Long getBindingId() { return bindingId; }
    public String getProviderCode() { return providerCode; }
    public String getSubjectType() { return subjectType; }
    public String getSubjectValue() { return subjectValue; }
    public boolean isPrimary() { return primary; }
    public IdentityBindingSubjectStatus getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public Instant getRevokedAt() { return revokedAt; }

    public void makePrimary() {
        requireActive();
        primary = true;
    }

    public void makeAlias() {
        requireActive();
        primary = false;
    }

    public void markSeen(Instant seenAt) {
        requireActive();
        if (seenAt != null
                && (lastSeenAt == null || seenAt.isAfter(lastSeenAt))) {
            lastSeenAt = seenAt;
        }
    }

    public void revoke(Instant revokedAt) {
        requireActive();
        primary = false;
        status = IdentityBindingSubjectStatus.REVOKED;
        this.revokedAt = java.util.Objects.requireNonNull(
                revokedAt,
                "revokedAt");
    }

    private void requireActive() {
        if (status != IdentityBindingSubjectStatus.ACTIVE) {
            throw new IllegalStateException(
                    "Revoked identity subject cannot be changed");
        }
    }
}
