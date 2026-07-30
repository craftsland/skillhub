package com.iflytek.skillhub.auth.entity;

import java.time.Clock;
import java.time.Instant;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "identity_binding",
       uniqueConstraints = @UniqueConstraint(columnNames = {"provider_code", "subject"}))
public class IdentityBinding {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "provider_code", nullable = false, length = 64)
    private String providerCode;

    @Column(nullable = false, length = 256)
    private String subject;

    @Column(name = "login_name", length = 128)
    private String loginName;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "extra_json", columnDefinition = "jsonb")
    private String extraJson;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private IdentityBindingStatus status = IdentityBindingStatus.ACTIVE;

    @Column(name = "last_authenticated_at")
    private Instant lastAuthenticatedAt;

    @Column(name = "last_synchronized_at")
    private Instant lastSynchronizedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoked_by", length = 128)
    private String revokedBy;

    @Column(name = "revocation_reason", length = 256)
    private String revocationReason;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected IdentityBinding() {}

    public IdentityBinding(String userId, String providerCode, String subject, String loginName) {
        this.userId = userId;
        this.providerCode = providerCode;
        this.subject = subject;
        this.loginName = loginName;
        this.status = IdentityBindingStatus.ACTIVE;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = Instant.now(Clock.systemUTC());
        this.updatedAt = this.createdAt;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = Instant.now(Clock.systemUTC());
    }

    public Long getId() { return id; }
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getProviderCode() { return providerCode; }
    public void setProviderCode(String providerCode) { this.providerCode = providerCode; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getLoginName() { return loginName; }
    public void setLoginName(String loginName) { this.loginName = loginName; }
    public String getExtraJson() { return extraJson; }
    public void setExtraJson(String extraJson) { this.extraJson = extraJson; }
    public IdentityBindingStatus getStatus() { return status; }
    public Instant getLastAuthenticatedAt() { return lastAuthenticatedAt; }
    public Instant getLastSynchronizedAt() { return lastSynchronizedAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevokedBy() { return revokedBy; }
    public String getRevocationReason() { return revocationReason; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void recordAuthentication(Instant authenticatedAt) {
        if (authenticatedAt != null
                && (lastAuthenticatedAt == null
                || authenticatedAt.isAfter(lastAuthenticatedAt))) {
            lastAuthenticatedAt = authenticatedAt;
        }
    }

    public void recordSynchronization(Instant synchronizedAt) {
        if (synchronizedAt != null
                && (lastSynchronizedAt == null
                || synchronizedAt.isAfter(lastSynchronizedAt))) {
            lastSynchronizedAt = synchronizedAt;
        }
    }
}
