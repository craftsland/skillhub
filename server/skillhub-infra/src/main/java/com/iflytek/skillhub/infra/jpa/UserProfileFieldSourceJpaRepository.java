package com.iflytek.skillhub.infra.jpa;

import com.iflytek.skillhub.domain.user.UserProfileFieldSource;
import com.iflytek.skillhub.domain.user.UserProfileFieldSourceId;
import com.iflytek.skillhub.domain.user.UserProfileFieldSourceRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserProfileFieldSourceJpaRepository
        extends JpaRepository<
                UserProfileFieldSource,
                UserProfileFieldSourceId>,
        UserProfileFieldSourceRepository {
}
