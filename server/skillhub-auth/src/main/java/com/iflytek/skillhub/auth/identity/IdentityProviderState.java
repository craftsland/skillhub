package com.iflytek.skillhub.auth.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "identity_provider_state")
class IdentityProviderState {

    @Id
    @Column(name = "provider_code", nullable = false, length = 64)
    private String providerCode;

    @Column(nullable = false, length = 32)
    private String protocol;

    @Column(length = 512)
    private String authority;

    @Column(name = "authority_fingerprint", length = 64)
    private String authorityFingerprint;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private IdentityProviderStatus state;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    protected IdentityProviderState() {
    }

    private IdentityProviderState(
            String providerCode,
            String protocol,
            String authority,
            String authorityFingerprint,
            IdentityProviderStatus state,
            Instant createdAt,
            Instant lastSeenAt) {
        this.providerCode = providerCode;
        this.protocol = protocol;
        this.authority = authority;
        this.authorityFingerprint = authorityFingerprint;
        this.state = state;
        this.createdAt = createdAt;
        this.lastSeenAt = lastSeenAt;
    }

    static IdentityProviderState ready(
            String providerCode,
            String protocol,
            String authority,
            String authorityFingerprint,
            Instant observedAt) {
        return new IdentityProviderState(
                providerCode,
                protocol,
                authority,
                authorityFingerprint,
                IdentityProviderStatus.READY,
                observedAt,
                observedAt);
    }

    static IdentityProviderState legacyUnpinned(
            String providerCode,
            String protocol,
            Instant createdAt) {
        return new IdentityProviderState(
                providerCode,
                protocol,
                null,
                null,
                IdentityProviderStatus.LEGACY_UNPINNED,
                createdAt,
                null);
    }

    static IdentityProviderState authorityMismatch(
            String providerCode,
            String protocol,
            String authority,
            String authorityFingerprint,
            Instant observedAt) {
        return new IdentityProviderState(
                providerCode,
                protocol,
                authority,
                authorityFingerprint,
                IdentityProviderStatus.AUTHORITY_MISMATCH,
                observedAt,
                observedAt);
    }

    String getProviderCode() {
        return providerCode;
    }

    String getProtocol() {
        return protocol;
    }

    String getAuthority() {
        return authority;
    }

    String getAuthorityFingerprint() {
        return authorityFingerprint;
    }

    IdentityProviderStatus getState() {
        return state;
    }

    Instant getCreatedAt() {
        return createdAt;
    }

    Instant getLastSeenAt() {
        return lastSeenAt;
    }
}
