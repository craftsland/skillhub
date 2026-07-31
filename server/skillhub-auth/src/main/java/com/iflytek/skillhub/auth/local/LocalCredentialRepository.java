package com.iflytek.skillhub.auth.local;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * JPA repository for username-password credentials linked to platform user accounts.
 */
@Repository
public interface LocalCredentialRepository extends JpaRepository<LocalCredential, Long> {

    Optional<LocalCredential> findByUsernameIgnoreCase(String username);

    Optional<LocalCredential> findByUserId(String userId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select credential
            from LocalCredential credential
            where lower(credential.username) = lower(:username)
            """)
    Optional<LocalCredential> findByUsernameIgnoreCaseForUpdate(
            @Param("username") String username);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select credential
            from LocalCredential credential
            where credential.userId = :userId
            """)
    Optional<LocalCredential> findByUserIdForUpdate(
            @Param("userId") String userId);

    boolean existsByUsernameIgnoreCase(String username);

    boolean existsByUserId(String userId);
}
