package com.iflytek.skillhub.auth.repository;

import com.iflytek.skillhub.auth.entity.IdentityLinkRequest;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import jakarta.persistence.LockModeType;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface IdentityLinkRequestRepository
        extends JpaRepository<IdentityLinkRequest, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select request
            from IdentityLinkRequest request
            where request.id = :requestId
            """)
    Optional<IdentityLinkRequest> findByIdForUpdate(
            @Param("requestId") UUID requestId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select request
            from IdentityLinkRequest request
            where request.primaryUserId = :userId
              and request.status in :statuses
            """)
    Optional<IdentityLinkRequest> findActiveByPrimaryUserIdForUpdate(
            @Param("userId") String userId,
            @Param("statuses")
                    Collection<IdentityLinkRequestStatus> statuses);
}
