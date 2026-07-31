package com.iflytek.skillhub.auth.merge;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountMergeIntentRepository
        extends JpaRepository<AccountMergeIntentEntity, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select intent
            from AccountMergeIntentEntity intent
            where intent.id = :intentId
            """)
    Optional<AccountMergeIntentEntity> findByIdForUpdate(
            @Param("intentId") UUID intentId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select intent
            from AccountMergeIntentEntity intent
            where (
                    intent.primaryUserId = :userId
                    or intent.secondaryUserId = :userId
                  )
              and intent.status in :statuses
            """)
    List<AccountMergeIntentEntity>
            findActiveByParticipantForUpdate(
                    @Param("userId") String userId,
                    @Param("statuses")
                            Collection<AccountMergeIntentStatus>
                                    statuses);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select intent
            from AccountMergeIntentEntity intent
            where intent.status in :statuses
              and intent.expiresAt <= :now
            order by intent.expiresAt, intent.id
            """)
    List<AccountMergeIntentEntity> findExpiredForUpdate(
            @Param("now") Instant now,
            @Param("statuses")
                    Collection<AccountMergeIntentStatus>
                            statuses,
            Pageable pageable);
}
