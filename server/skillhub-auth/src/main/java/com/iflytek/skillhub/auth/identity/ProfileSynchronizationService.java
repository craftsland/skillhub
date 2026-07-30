package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserProfileFieldAssurance;
import com.iflytek.skillhub.domain.user.UserProfileFieldName;
import com.iflytek.skillhub.domain.user.UserProfileFieldSource;
import com.iflytek.skillhub.domain.user.UserProfileFieldSourceRepository;
import com.iflytek.skillhub.domain.user.UserProfileFieldSourceType;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;

@Service
class ProfileSynchronizationService {

    private final UserProfileFieldSourceRepository sourceRepository;
    private final Clock clock;

    ProfileSynchronizationService(
            UserProfileFieldSourceRepository sourceRepository,
            Clock clock) {
        this.sourceRepository = sourceRepository;
        this.clock = clock;
    }

    void synchronize(
            UserAccount user,
            IdentityAssertion assertion,
            ProviderDescriptor descriptor,
            boolean accountCreated) {
        Map<String, UserProfileFieldSource> sources =
                sourcesByField(user.getId());
        Instant synchronizedAt =
                assertion.evidence().authenticatedAt();
        Instant updatedAt = Instant.now(clock);
        ExternalProfile profile = assertion.profile();
        String providerCode =
                assertion.provider().providerCode();
        ProfileSyncPolicy policy = descriptor.profileSyncPolicy();
        if (!accountCreated) {
            backfillMissingLocalSources(
                    user,
                    updatedAt,
                    sources);
        }

        synchronizeField(
                user,
                UserProfileFieldName.DISPLAY_NAME,
                Optional.of(profile.displayName()),
                UserProfileFieldAssurance.PROVIDER_ASSERTED,
                policy.displayName(),
                accountCreated,
                providerCode,
                synchronizedAt,
                updatedAt,
                user::getDisplayName,
                user::setDisplayName,
                sources);
        synchronizeField(
                user,
                UserProfileFieldName.EMAIL,
                trustedEmail(profile),
                profile.email()
                        .map(EmailClaim::assurance)
                        .map(this::profileAssurance)
                        .orElse(
                                UserProfileFieldAssurance.UNVERIFIED),
                policy.email(),
                accountCreated,
                providerCode,
                synchronizedAt,
                updatedAt,
                user::getEmail,
                user::setEmail,
                sources);
        synchronizeField(
                user,
                UserProfileFieldName.AVATAR_URL,
                profile.avatarUrl().map(Object::toString),
                UserProfileFieldAssurance.PROVIDER_ASSERTED,
                policy.avatarUrl(),
                accountCreated,
                providerCode,
                synchronizedAt,
                updatedAt,
                user::getAvatarUrl,
                user::setAvatarUrl,
                sources);

        if (accountCreated
                && policy.displayName() == ProfileSyncMode.NEVER) {
            markFallbackDisplayName(
                    user,
                    updatedAt,
                    sources);
        }
    }

    private void synchronizeField(
            UserAccount user,
            UserProfileFieldName field,
            Optional<String> candidate,
            UserProfileFieldAssurance assurance,
            ProfileSyncMode mode,
            boolean accountCreated,
            String providerCode,
            Instant synchronizedAt,
            Instant updatedAt,
            Supplier<String> currentValue,
            Consumer<String> updateValue,
            Map<String, UserProfileFieldSource> sources) {
        if (candidate.isEmpty()) {
            return;
        }
        UserProfileFieldSource currentSource =
                sources.get(field.databaseValue());
        if (!shouldSynchronize(
                mode,
                accountCreated,
                currentValue.get(),
                currentSource,
                providerCode)) {
            return;
        }

        updateValue.accept(candidate.orElseThrow());
        UserProfileFieldSource source = currentSource == null
                ? UserProfileFieldSource.provider(
                        user.getId(),
                        field,
                        providerCode,
                        assurance,
                        synchronizedAt,
                        updatedAt)
                : currentSource;
        if (currentSource != null) {
            source.markProvider(
                    providerCode,
                    assurance,
                    synchronizedAt,
                    updatedAt);
        }
        source = sourceRepository.save(source);
        sources.put(field.databaseValue(), source);
    }

    private boolean shouldSynchronize(
            ProfileSyncMode mode,
            boolean accountCreated,
            String currentValue,
            UserProfileFieldSource source,
            String providerCode) {
        return switch (mode) {
            case NEVER -> false;
            case INITIAL_ONLY -> accountCreated;
            case FILL_IF_EMPTY ->
                    accountCreated || isBlank(currentValue);
            case PRESERVE_LOCAL -> accountCreated
                    || source == null && isBlank(currentValue)
                    || sameProvider(source, providerCode);
            case PROVIDER_AUTHORITATIVE -> true;
        };
    }

    private boolean sameProvider(
            UserProfileFieldSource source,
            String providerCode) {
        return source != null
                && source.getSourceType()
                        == UserProfileFieldSourceType.PROVIDER
                && providerCode.equals(source.getProviderCode());
    }

    private void markFallbackDisplayName(
            UserAccount user,
            Instant updatedAt,
            Map<String, UserProfileFieldSource> sources) {
        if (sources.containsKey(
                UserProfileFieldName.DISPLAY_NAME.databaseValue())) {
            return;
        }
        UserProfileFieldSource fallback =
                UserProfileFieldSource.local(
                        user.getId(),
                        UserProfileFieldName.DISPLAY_NAME,
                        UserProfileFieldSourceType.LEGACY_LOCAL,
                        updatedAt);
        fallback = sourceRepository.save(fallback);
        sources.put(fallback.getFieldName(), fallback);
    }

    private void backfillMissingLocalSources(
            UserAccount user,
            Instant updatedAt,
            Map<String, UserProfileFieldSource> sources) {
        backfillMissingLocalSource(
                user,
                UserProfileFieldName.DISPLAY_NAME,
                user.getDisplayName(),
                updatedAt,
                sources);
        backfillMissingLocalSource(
                user,
                UserProfileFieldName.EMAIL,
                user.getEmail(),
                updatedAt,
                sources);
        backfillMissingLocalSource(
                user,
                UserProfileFieldName.AVATAR_URL,
                user.getAvatarUrl(),
                updatedAt,
                sources);
    }

    private void backfillMissingLocalSource(
            UserAccount user,
            UserProfileFieldName field,
            String value,
            Instant updatedAt,
            Map<String, UserProfileFieldSource> sources) {
        if (isBlank(value)
                || sources.containsKey(field.databaseValue())) {
            return;
        }
        UserProfileFieldSource source =
                UserProfileFieldSource.local(
                        user.getId(),
                        field,
                        UserProfileFieldSourceType.LEGACY_LOCAL,
                        updatedAt);
        source = sourceRepository.save(source);
        sources.put(field.databaseValue(), source);
    }

    private Map<String, UserProfileFieldSource> sourcesByField(
            String userId) {
        LinkedHashMap<String, UserProfileFieldSource> sources =
                new LinkedHashMap<>();
        for (UserProfileFieldSource source :
                sourceRepository.findByUserId(userId)) {
            UserProfileFieldSource duplicate =
                    sources.put(source.getFieldName(), source);
            if (duplicate != null) {
                throw new IllegalStateException(
                        "Duplicate profile field source");
            }
        }
        return sources;
    }

    private Optional<String> trustedEmail(ExternalProfile profile) {
        return profile.email()
                .filter(claim -> claim.assurance()
                        .isVerifiedOrAuthoritative())
                .map(EmailClaim::value);
    }

    private UserProfileFieldAssurance profileAssurance(
            EmailAssurance assurance) {
        return switch (assurance) {
            case UNVERIFIED ->
                    UserProfileFieldAssurance.UNVERIFIED;
            case PROVIDER_ASSERTED ->
                    UserProfileFieldAssurance.PROVIDER_ASSERTED;
            case VERIFIED ->
                    UserProfileFieldAssurance.VERIFIED;
            case AUTHORITATIVE ->
                    UserProfileFieldAssurance.AUTHORITATIVE;
        };
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
