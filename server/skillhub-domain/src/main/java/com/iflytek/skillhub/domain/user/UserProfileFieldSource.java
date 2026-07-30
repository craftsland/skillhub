package com.iflytek.skillhub.domain.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Objects;

@Entity
@Table(name = "user_profile_field_source")
@IdClass(UserProfileFieldSourceId.class)
public class UserProfileFieldSource {

    @Id
    @Column(name = "user_id", length = 128)
    private String userId;

    @Id
    @Column(name = "field_name", length = 32)
    private String fieldName;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 32)
    private UserProfileFieldSourceType sourceType;

    @Column(name = "provider_code", length = 64)
    private String providerCode;

    @Enumerated(EnumType.STRING)
    @Column(length = 32)
    private UserProfileFieldAssurance assurance;

    @Column(name = "last_synchronized_at")
    private Instant lastSynchronizedAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected UserProfileFieldSource() {
    }

    private UserProfileFieldSource(
            String userId,
            UserProfileFieldName fieldName,
            UserProfileFieldSourceType sourceType,
            String providerCode,
            UserProfileFieldAssurance assurance,
            Instant lastSynchronizedAt,
            Instant updatedAt) {
        this.userId = requireUserId(userId);
        this.fieldName = Objects.requireNonNull(
                fieldName,
                "fieldName").databaseValue();
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt");
        update(
                sourceType,
                providerCode,
                assurance,
                lastSynchronizedAt,
                updatedAt);
    }

    public static UserProfileFieldSource provider(
            String userId,
            UserProfileFieldName fieldName,
            String providerCode,
            UserProfileFieldAssurance assurance,
            Instant synchronizedAt,
            Instant updatedAt) {
        return new UserProfileFieldSource(
                userId,
                fieldName,
                UserProfileFieldSourceType.PROVIDER,
                providerCode,
                assurance,
                synchronizedAt,
                updatedAt);
    }

    public static UserProfileFieldSource local(
            String userId,
            UserProfileFieldName fieldName,
            UserProfileFieldSourceType sourceType,
            Instant updatedAt) {
        if (sourceType == UserProfileFieldSourceType.PROVIDER) {
            throw new IllegalArgumentException(
                    "Provider source requires provider metadata");
        }
        return new UserProfileFieldSource(
                userId,
                fieldName,
                sourceType,
                null,
                null,
                null,
                updatedAt);
    }

    public void markProvider(
            String providerCode,
            UserProfileFieldAssurance assurance,
            Instant synchronizedAt,
            Instant updatedAt) {
        update(
                UserProfileFieldSourceType.PROVIDER,
                providerCode,
                assurance,
                synchronizedAt,
                updatedAt);
    }

    public void markLocal(
            UserProfileFieldSourceType sourceType,
            Instant updatedAt) {
        if (sourceType == UserProfileFieldSourceType.PROVIDER) {
            throw new IllegalArgumentException(
                    "Provider source requires provider metadata");
        }
        update(sourceType, null, null, null, updatedAt);
    }

    private void update(
            UserProfileFieldSourceType sourceType,
            String providerCode,
            UserProfileFieldAssurance assurance,
            Instant lastSynchronizedAt,
            Instant updatedAt) {
        this.sourceType = Objects.requireNonNull(
                sourceType,
                "sourceType");
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt");
        if (sourceType == UserProfileFieldSourceType.PROVIDER) {
            this.providerCode = requireProviderCode(providerCode);
            this.assurance = Objects.requireNonNull(
                    assurance,
                    "assurance");
            this.lastSynchronizedAt = Objects.requireNonNull(
                    lastSynchronizedAt,
                    "lastSynchronizedAt");
            return;
        }
        this.providerCode = null;
        this.assurance = null;
        this.lastSynchronizedAt = null;
    }

    private static String requireUserId(String value) {
        Objects.requireNonNull(value, "userId");
        if (value.isBlank() || value.length() > 128) {
            throw new IllegalArgumentException("Invalid user id");
        }
        return value;
    }

    private static String requireProviderCode(String value) {
        Objects.requireNonNull(value, "providerCode");
        if (value.isBlank() || value.length() > 64) {
            throw new IllegalArgumentException(
                    "Invalid identity provider code");
        }
        return value;
    }

    public String getUserId() {
        return userId;
    }

    public String getFieldName() {
        return fieldName;
    }

    public UserProfileFieldSourceType getSourceType() {
        return sourceType;
    }

    public String getProviderCode() {
        return providerCode;
    }

    public UserProfileFieldAssurance getAssurance() {
        return assurance;
    }

    public Instant getLastSynchronizedAt() {
        return lastSynchronizedAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
