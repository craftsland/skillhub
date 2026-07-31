package com.iflytek.skillhub.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * PostgreSQL lease queue for reliable secondary-session revocation.
 *
 * <p>Direct SQL is required because claiming work must combine
 * {@code FOR UPDATE SKIP LOCKED}, lease recovery, and an atomic state update.
 * This is a command repository for an app-owned operational queue, not a
 * presentation query repository.
 */
@Repository
public class AccountMergeSessionRevocationRepository {

    private final JdbcTemplate jdbcTemplate;

    public AccountMergeSessionRevocationRepository(
            JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public Optional<Claim> claimNext(
            Instant now,
            Duration leaseDuration) {
        Instant leaseUntil = now.plus(leaseDuration);
        return jdbcTemplate.query(
                """
                WITH due AS (
                    SELECT id
                    FROM account_merge_session_revocation
                    WHERE (
                        status = 'PENDING'
                        AND next_attempt_at <= ?
                    ) OR (
                        status = 'PROCESSING'
                        AND lease_until <= ?
                    )
                    ORDER BY id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE account_merge_session_revocation task
                SET status = 'PROCESSING',
                    attempt_count = task.attempt_count + 1,
                    lease_until = ?,
                    updated_at = ?
                FROM due
                WHERE task.id = due.id
                RETURNING task.id,
                          task.user_id,
                          task.attempt_count,
                          task.lease_until
                """,
                resultSet -> resultSet.next()
                        ? Optional.of(mapClaim(resultSet))
                        : Optional.empty(),
                atOffset(now),
                atOffset(now),
                atOffset(leaseUntil),
                atOffset(now));
    }

    public boolean complete(
            Claim claim,
            Instant completedAt) {
        return jdbcTemplate.update(
                """
                UPDATE account_merge_session_revocation
                SET status = 'COMPLETED',
                    lease_until = NULL,
                    completed_at = ?,
                    last_error_code = NULL,
                    updated_at = ?
                WHERE id = ?
                  AND status = 'PROCESSING'
                  AND attempt_count = ?
                """,
                atOffset(completedAt),
                atOffset(completedAt),
                claim.id(),
                claim.attemptCount()) == 1;
    }

    public boolean retry(
            Claim claim,
            Instant nextAttemptAt,
            String errorCode,
            Instant updatedAt) {
        return jdbcTemplate.update(
                """
                UPDATE account_merge_session_revocation
                SET status = 'PENDING',
                    lease_until = NULL,
                    next_attempt_at = ?,
                    last_error_code = ?,
                    updated_at = ?
                WHERE id = ?
                  AND status = 'PROCESSING'
                  AND attempt_count = ?
                """,
                atOffset(nextAttemptAt),
                errorCode,
                atOffset(updatedAt),
                claim.id(),
                claim.attemptCount()) == 1;
    }

    private Claim mapClaim(ResultSet resultSet)
            throws SQLException {
        return new Claim(
                resultSet.getLong("id"),
                resultSet.getString("user_id"),
                resultSet.getInt("attempt_count"),
                resultSet.getObject(
                                "lease_until",
                                OffsetDateTime.class)
                        .toInstant());
    }

    private OffsetDateTime atOffset(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }

    public record Claim(
            long id,
            String userId,
            int attemptCount,
            Instant leaseUntil
    ) {
    }
}
