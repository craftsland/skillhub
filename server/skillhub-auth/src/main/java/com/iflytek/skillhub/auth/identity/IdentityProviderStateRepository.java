package com.iflytek.skillhub.auth.identity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * PostgreSQL compare-and-set operations for the provider authority lock.
 *
 * <p>Native SQL is required here because authority pinning must use
 * {@code INSERT ... ON CONFLICT DO NOTHING} and state-guarded updates in the
 * database. A read-then-save JPA sequence would allow concurrent application
 * instances to overwrite the authority chosen by another instance.
 */
@Repository
interface IdentityProviderStateRepository
        extends JpaRepository<IdentityProviderState, String> {

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            INSERT INTO identity_provider_state (
                provider_code,
                protocol,
                authority,
                authority_fingerprint,
                state,
                created_at,
                last_seen_at
            ) VALUES (
                :providerCode,
                :protocol,
                :authority,
                :fingerprint,
                'READY',
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
            )
            ON CONFLICT (provider_code) DO NOTHING
            """, nativeQuery = true)
    int insertReady(
            @Param("providerCode") String providerCode,
            @Param("protocol") String protocol,
            @Param("authority") String authority,
            @Param("fingerprint") String fingerprint);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            INSERT INTO identity_provider_state (
                provider_code,
                protocol,
                authority,
                authority_fingerprint,
                state,
                created_at,
                last_seen_at
            ) VALUES (
                :providerCode,
                :protocol,
                NULL,
                NULL,
                'LEGACY_UNPINNED',
                CURRENT_TIMESTAMP,
                NULL
            )
            ON CONFLICT (provider_code) DO NOTHING
            """, nativeQuery = true)
    int insertLegacyUnpinned(
            @Param("providerCode") String providerCode,
            @Param("protocol") String protocol);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE identity_provider_state
               SET authority = :authority,
                   authority_fingerprint = :fingerprint,
                   state = 'READY',
                   last_seen_at = CURRENT_TIMESTAMP
             WHERE provider_code = :providerCode
               AND protocol = :protocol
               AND state = 'LEGACY_UNPINNED'
               AND authority IS NULL
               AND authority_fingerprint IS NULL
            """, nativeQuery = true)
    int pinLegacy(
            @Param("providerCode") String providerCode,
            @Param("protocol") String protocol,
            @Param("authority") String authority,
            @Param("fingerprint") String fingerprint);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE identity_provider_state
               SET state = 'MISCONFIGURED',
                   last_seen_at = CURRENT_TIMESTAMP
             WHERE provider_code = :providerCode
               AND state = 'LEGACY_UNPINNED'
               AND authority IS NULL
               AND authority_fingerprint IS NULL
               AND protocol <> :protocol
            """, nativeQuery = true)
    int markLegacyProtocolMismatch(
            @Param("providerCode") String providerCode,
            @Param("protocol") String protocol);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE identity_provider_state
               SET state = 'AUTHORITY_MISMATCH',
                   last_seen_at = CURRENT_TIMESTAMP
             WHERE provider_code = :providerCode
               AND state IN ('READY', 'DEGRADED')
               AND authority_fingerprint IS NOT NULL
               AND (
                   protocol <> :protocol
                   OR authority_fingerprint <> :fingerprint
               )
            """, nativeQuery = true)
    int markAuthorityMismatch(
            @Param("providerCode") String providerCode,
            @Param("protocol") String protocol,
            @Param("fingerprint") String fingerprint);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE identity_provider_state
               SET state = 'READY',
                   last_seen_at = CURRENT_TIMESTAMP
             WHERE provider_code = :providerCode
               AND state = 'AUTHORITY_MISMATCH'
               AND protocol = :protocol
               AND authority_fingerprint = :fingerprint
            """, nativeQuery = true)
    int recoverSameAuthority(
            @Param("providerCode") String providerCode,
            @Param("protocol") String protocol,
            @Param("fingerprint") String fingerprint);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE identity_provider_state
               SET last_seen_at = CURRENT_TIMESTAMP
             WHERE provider_code = :providerCode
               AND state = 'READY'
               AND protocol = :protocol
               AND authority_fingerprint = :fingerprint
            """, nativeQuery = true)
    int touchReady(
            @Param("providerCode") String providerCode,
            @Param("protocol") String protocol,
            @Param("fingerprint") String fingerprint);
}
