package com.iflytek.skillhub.domain.user;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.Objects;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserProfileFieldSourceService {

    private final UserProfileFieldSourceRepository repository;
    private final Clock clock;

    public UserProfileFieldSourceService(
            UserProfileFieldSourceRepository repository,
            Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional
    public void markUserProvided(
            String userId,
            Collection<UserProfileFieldName> fields) {
        markLocal(
                userId,
                fields,
                UserProfileFieldSourceType.USER);
    }

    @Transactional
    public void markAdminProvided(
            String userId,
            Collection<UserProfileFieldName> fields) {
        markLocal(
                userId,
                fields,
                UserProfileFieldSourceType.ADMIN);
    }

    private void markLocal(
            String userId,
            Collection<UserProfileFieldName> fields,
            UserProfileFieldSourceType sourceType) {
        Objects.requireNonNull(fields, "fields");
        Instant updatedAt = Instant.now(clock);
        for (UserProfileFieldName field : fields) {
            UserProfileFieldSource source = repository
                    .findByUserIdAndFieldName(
                            userId,
                            field.databaseValue())
                    .orElseGet(() -> UserProfileFieldSource.local(
                            userId,
                            field,
                            sourceType,
                            updatedAt));
            source.markLocal(sourceType, updatedAt);
            repository.save(source);
        }
    }
}
