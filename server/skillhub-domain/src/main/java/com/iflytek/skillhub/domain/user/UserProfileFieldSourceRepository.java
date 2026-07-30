package com.iflytek.skillhub.domain.user;

import java.util.List;
import java.util.Optional;

public interface UserProfileFieldSourceRepository {

    Optional<UserProfileFieldSource> findByUserIdAndFieldName(
            String userId,
            String fieldName);

    List<UserProfileFieldSource> findByUserId(String userId);

    UserProfileFieldSource save(UserProfileFieldSource source);
}
