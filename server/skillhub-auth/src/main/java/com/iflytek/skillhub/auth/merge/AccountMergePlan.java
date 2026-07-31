package com.iflytek.skillhub.auth.merge;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Credential-free, deterministic migration plan for one account merge.
 *
 * <p>The digest covers the complete server-side snapshot. Public preview
 * fields intentionally contain no provider subject, password material, token
 * hash, session identifier, or raw proof.
 */
public record AccountMergePlan(
        String digest,
        List<String> identityProviders,
        LocalCredentialAction localCredentialAction,
        List<String> blockedPlatformRoles,
        List<NamespaceChange> namespaceChanges,
        List<ApiTokenView> apiTokensToRevoke,
        int skillOwnershipCount,
        SocialSummary social,
        NotificationSummary notifications,
        List<Conflict> conflicts
) {
    private static final Pattern SHA256_PATTERN =
            Pattern.compile("[0-9a-f]{64}");

    public AccountMergePlan {
        if (digest == null
                || !SHA256_PATTERN.matcher(digest).matches()) {
            throw new IllegalArgumentException(
                    "Invalid account merge plan digest");
        }
        identityProviders = List.copyOf(identityProviders);
        Objects.requireNonNull(
                localCredentialAction,
                "localCredentialAction");
        blockedPlatformRoles =
                List.copyOf(blockedPlatformRoles);
        namespaceChanges = List.copyOf(namespaceChanges);
        apiTokensToRevoke = List.copyOf(apiTokensToRevoke);
        if (skillOwnershipCount < 0) {
            throw new IllegalArgumentException(
                    "Invalid account merge skill count");
        }
        Objects.requireNonNull(social, "social");
        Objects.requireNonNull(notifications, "notifications");
        conflicts = List.copyOf(conflicts);
    }

    public boolean confirmable() {
        return conflicts.isEmpty();
    }

    public enum LocalCredentialAction {
        NONE,
        MOVE_SECONDARY,
        KEEP_PRIMARY_DELETE_SECONDARY
    }

    public enum ConflictCode {
        IDENTITY_PROVIDER_CONFLICT(
                ConflictResolutionAction
                        .REMOVE_DUPLICATE_IDENTITY),
        PLATFORM_ROLE_CONFLICT(
                ConflictResolutionAction
                        .REMOVE_SECONDARY_PLATFORM_ROLE),
        NAMESPACE_OWNER_CONFLICT(
                ConflictResolutionAction
                        .TRANSFER_NAMESPACE_OWNERSHIP),
        SKILL_OWNERSHIP_CONFLICT(
                ConflictResolutionAction
                        .REASSIGN_OR_RENAME_SKILL),
        ACTIVE_IDENTITY_LINK(
                ConflictResolutionAction
                        .COMPLETE_OR_CANCEL_IDENTITY_LINK),
        PENDING_PROFILE_CHANGE(
                ConflictResolutionAction
                        .COMPLETE_OR_CANCEL_PROFILE_CHANGE);

        private final ConflictResolutionAction
                suggestedAction;

        ConflictCode(
                ConflictResolutionAction suggestedAction) {
            this.suggestedAction = suggestedAction;
        }

        public ConflictResolutionAction suggestedAction() {
            return suggestedAction;
        }
    }

    public enum ConflictResolutionAction {
        REMOVE_DUPLICATE_IDENTITY,
        REMOVE_SECONDARY_PLATFORM_ROLE,
        TRANSFER_NAMESPACE_OWNERSHIP,
        REASSIGN_OR_RENAME_SKILL,
        COMPLETE_OR_CANCEL_IDENTITY_LINK,
        COMPLETE_OR_CANCEL_PROFILE_CHANGE
    }

    public record NamespaceChange(
            long namespaceId,
            String namespaceSlug,
            String primaryRole,
            String secondaryRole,
            String resultingRole,
            boolean blocked
    ) {
        public NamespaceChange {
            if (namespaceId <= 0) {
                throw new IllegalArgumentException(
                        "Invalid namespace id");
            }
            namespaceSlug = requireText(
                    namespaceSlug,
                    "namespaceSlug");
            secondaryRole = requireText(
                    secondaryRole,
                    "secondaryRole");
            resultingRole = requireText(
                    resultingRole,
                    "resultingRole");
        }
    }

    public record ApiTokenView(
            String name,
            String prefix
    ) {
        public ApiTokenView {
            name = requireText(name, "tokenName");
            prefix = requireText(prefix, "tokenPrefix");
        }
    }

    public record SocialSummary(
            int starsMoved,
            int duplicateStarsDiscarded,
            int ratingsMoved,
            int duplicateRatingsDiscarded,
            int subscriptionsMoved,
            int duplicateSubscriptionsDiscarded,
            List<DiscardedRating> discardedRatings
    ) {
        public SocialSummary {
            if (starsMoved < 0
                    || duplicateStarsDiscarded < 0
                    || ratingsMoved < 0
                    || duplicateRatingsDiscarded < 0
                    || subscriptionsMoved < 0
                    || duplicateSubscriptionsDiscarded < 0) {
                throw new IllegalArgumentException(
                        "Invalid account merge social summary");
            }
            discardedRatings = List.copyOf(
                    discardedRatings);
            if (discardedRatings.size()
                    != duplicateRatingsDiscarded) {
                throw new IllegalArgumentException(
                        "Discarded rating details must match count");
            }
        }

        public SocialSummary(
                int starsMoved,
                int duplicateStarsDiscarded,
                int ratingsMoved,
                int duplicateRatingsDiscarded,
                int subscriptionsMoved,
                int duplicateSubscriptionsDiscarded) {
            this(
                    starsMoved,
                    duplicateStarsDiscarded,
                    ratingsMoved,
                    duplicateRatingsDiscarded,
                    subscriptionsMoved,
                    duplicateSubscriptionsDiscarded,
                    List.of());
            if (duplicateRatingsDiscarded != 0) {
                throw new IllegalArgumentException(
                        "Discarded rating details are required");
            }
        }
    }

    public record DiscardedRating(
            long skillId,
            int score
    ) {
        public DiscardedRating {
            if (skillId <= 0 || score < 1 || score > 5) {
                throw new IllegalArgumentException(
                        "Invalid discarded account merge rating");
            }
        }
    }

    public record NotificationSummary(
            int notificationsMoved,
            int preferencesMoved,
            int duplicatePreferencesDiscarded,
            int governanceNotificationsMoved
    ) {
        public NotificationSummary {
            if (notificationsMoved < 0
                    || preferencesMoved < 0
                    || duplicatePreferencesDiscarded < 0
                    || governanceNotificationsMoved < 0) {
                throw new IllegalArgumentException(
                        "Invalid account merge notification summary");
            }
        }
    }

    public record Conflict(
            ConflictCode code,
            String resource,
            ConflictResolutionAction suggestedAction
    ) {
        public Conflict {
            Objects.requireNonNull(code, "code");
            resource = requireText(resource, "resource");
            Objects.requireNonNull(
                    suggestedAction,
                    "suggestedAction");
            if (suggestedAction != code.suggestedAction()) {
                throw new IllegalArgumentException(
                        "Conflict action does not match code");
            }
        }

        public Conflict(
                ConflictCode code,
                String resource) {
            this(
                    code,
                    resource,
                    Objects.requireNonNull(
                            code,
                            "code").suggestedAction());
        }
    }

    private static String requireText(
            String value,
            String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "Invalid account merge " + fieldName);
        }
        return value;
    }
}
