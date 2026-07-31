package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.auth.merge.AccountMergeIntentStatus;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Credential-free account merge preview.
 */
public record AccountMergePreviewResponse(
        UUID intentId,
        AccountMergeIntentStatus status,
        int previewVersion,
        Instant expiresAt,
        boolean confirmable,
        List<String> identityProviders,
        String localCredentialAction,
        List<String> blockedPlatformRoles,
        List<NamespaceChange> namespaceChanges,
        List<ApiToken> apiTokensToRevoke,
        int skillOwnershipCount,
        SocialSummary social,
        NotificationSummary notifications,
        List<Conflict> conflicts
) {
    public record NamespaceChange(
            long namespaceId,
            String namespaceSlug,
            String primaryRole,
            String secondaryRole,
            String resultingRole,
            boolean blocked
    ) {
    }

    public record ApiToken(
            String name,
            String prefix
    ) {
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
    }

    public record DiscardedRating(
            long skillId,
            int score
    ) {
    }

    public record NotificationSummary(
            int notificationsMoved,
            int preferencesMoved,
            int duplicatePreferencesDiscarded,
            int governanceNotificationsMoved
    ) {
    }

    public record Conflict(
            String code,
            String resource,
            String suggestedAction
    ) {
    }
}
