package com.iflytek.skillhub.auth.repository;

import com.iflytek.skillhub.auth.entity.IdentityBindingSubject;
import com.iflytek.skillhub.auth.entity.IdentityBindingSubjectStatus;
import jakarta.persistence.LockModeType;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface IdentityBindingSubjectRepository
        extends JpaRepository<IdentityBindingSubject, Long>,
        IdentityBindingSubjectLookupRepository {

    @Modifying(
            flushAutomatically = true,
            clearAutomatically = true)
    @Query("""
            update IdentityBindingSubject subject
            set subject.primary = false
            where subject.bindingId = :bindingId
              and subject.status = :status
              and subject.primary = true
            """)
    int demoteActivePrimary(
            @Param("bindingId") Long bindingId,
            @Param("status") IdentityBindingSubjectStatus status);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select subject
            from IdentityBindingSubject subject
            where subject.bindingId = :bindingId
              and subject.status = :status
            order by subject.id
            """)
    List<IdentityBindingSubject> findByBindingIdAndStatusForUpdate(
            @Param("bindingId") Long bindingId,
            @Param("status") IdentityBindingSubjectStatus status);
}
