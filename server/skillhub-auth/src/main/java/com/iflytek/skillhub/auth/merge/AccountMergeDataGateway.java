package com.iflytek.skillhub.auth.merge;

import java.time.Instant;
import java.util.UUID;

/**
 * Cross-aggregate persistence boundary for account-merge planning and
 * migration.
 *
 * <p>The implementation lives in {@code skillhub-app}, which can see every
 * participating module. Both methods run inside the caller's PostgreSQL
 * transaction.
 */
public interface AccountMergeDataGateway {

    AccountMergePlan inspect(
            String primaryUserId,
            String secondaryUserId,
            Instant now);

    void apply(
            String primaryUserId,
            String secondaryUserId,
            UUID intentId,
            AccountMergePlan plan,
            Instant now);
}
