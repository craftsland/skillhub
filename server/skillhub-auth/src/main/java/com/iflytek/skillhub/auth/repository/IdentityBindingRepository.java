package com.iflytek.skillhub.auth.repository;

import com.iflytek.skillhub.auth.entity.IdentityBinding;
import com.iflytek.skillhub.auth.entity.IdentityBindingStatus;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * JPA repository for links between platform users and external identity-provider subjects.
 */
@Repository
public interface IdentityBindingRepository extends JpaRepository<IdentityBinding, Long> {
    Optional<IdentityBinding> findByProviderCodeAndSubjectAndStatus(
            String providerCode,
            String subject,
            IdentityBindingStatus status);

    @Query("""
            select distinct binding.providerCode
            from IdentityBinding binding
            order by binding.providerCode
            """)
    List<String> findDistinctProviderCodes();

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select binding
            from IdentityBinding binding
            where binding.id = :bindingId
              and binding.status = :status
            """)
    Optional<IdentityBinding> findByIdAndStatusForUpdate(
            @Param("bindingId") Long bindingId,
            @Param("status") IdentityBindingStatus status);

    boolean existsByProviderCode(String providerCode);

    List<IdentityBinding> findByUserId(String userId);

    List<IdentityBinding> findByUserIdAndStatus(
            String userId,
            IdentityBindingStatus status);
}
