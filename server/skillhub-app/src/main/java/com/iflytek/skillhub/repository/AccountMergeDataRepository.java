package com.iflytek.skillhub.repository;

import com.iflytek.skillhub.auth.merge.AccountMergeDataGateway;
import com.iflytek.skillhub.auth.merge.AccountMergePlan;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.ApiTokenView;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.Conflict;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.ConflictCode;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.DiscardedRating;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.LocalCredentialAction;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.NamespaceChange;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.NotificationSummary;
import com.iflytek.skillhub.auth.merge.AccountMergePlan.SocialSummary;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * PostgreSQL implementation of the Account Merge cross-aggregate boundary.
 *
 * <p>Direct SQL is intentional here: one confirmation must inspect and mutate
 * authentication, authorization, skill, social, notification, and transient
 * security tables in one serializable transaction. Routing the workflow
 * through each aggregate repository would make the snapshot and lock order
 * implicit and would risk partially applying the merge.
 */
@Repository
public class AccountMergeDataRepository
        implements AccountMergeDataGateway {

    private final JdbcTemplate jdbcTemplate;

    public AccountMergeDataRepository(
            JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public AccountMergePlan inspect(
            String primaryUserId,
            String secondaryUserId,
            Instant now) {
        SnapshotDigest digest = new SnapshotDigest();
        List<Conflict> conflicts = new ArrayList<>();

        List<AccountRow> accounts = accounts(
                primaryUserId,
                secondaryUserId);
        digest.rows("account", accounts);

        List<BindingRow> bindings = bindings(
                primaryUserId,
                secondaryUserId);
        digest.rows("binding", bindings);
        Set<String> primaryProviders = providers(
                bindings,
                primaryUserId);
        Set<String> secondaryProviders = providers(
                bindings,
                secondaryUserId);
        primaryProviders.stream()
                .filter(secondaryProviders::contains)
                .sorted()
                .forEach(provider -> conflicts.add(
                        new Conflict(
                                ConflictCode
                                        .IDENTITY_PROVIDER_CONFLICT,
                                provider)));

        List<CredentialRow> credentials = credentials(
                primaryUserId,
                secondaryUserId);
        digest.rows("credential", credentials);
        boolean primaryCredential = credentials.stream()
                .anyMatch(row -> row.userId().equals(
                        primaryUserId));
        boolean secondaryCredential = credentials.stream()
                .anyMatch(row -> row.userId().equals(
                        secondaryUserId));
        LocalCredentialAction credentialAction =
                localCredentialAction(
                        primaryCredential,
                        secondaryCredential);

        List<RoleRow> roles = roles(
                primaryUserId,
                secondaryUserId);
        digest.rows("role", roles);
        List<String> blockedRoles = roles.stream()
                .filter(row -> row.userId().equals(
                        secondaryUserId))
                .map(RoleRow::roleCode)
                .distinct()
                .sorted()
                .toList();
        blockedRoles.forEach(role -> conflicts.add(
                new Conflict(
                        ConflictCode.PLATFORM_ROLE_CONFLICT,
                        role)));

        List<WorkflowRow> activeLinks = activeIdentityLinks(
                primaryUserId,
                secondaryUserId,
                now);
        digest.rows("identity-link", activeLinks);
        activeLinks.forEach(link -> conflicts.add(
                new Conflict(
                        ConflictCode.ACTIVE_IDENTITY_LINK,
                        link.providerCode())));

        List<MembershipRow> memberships = memberships(
                primaryUserId,
                secondaryUserId);
        digest.rows("membership", memberships);
        List<NamespaceChange> namespaceChanges =
                namespaceChanges(
                        memberships,
                        primaryUserId,
                        secondaryUserId,
                        conflicts);

        List<TokenRow> tokens = unrevokedTokens(
                secondaryUserId);
        digest.rows("api-token", tokens);
        List<ApiTokenView> tokenViews = tokens.stream()
                .map(token -> new ApiTokenView(
                        token.name(),
                        token.prefix()))
                .toList();

        List<SkillRow> skills = ownedSkills(
                primaryUserId,
                secondaryUserId);
        digest.rows("skill", skills);
        Set<String> primarySkillCoordinates = skills.stream()
                .filter(skill -> skill.userId().equals(
                        primaryUserId))
                .map(SkillRow::coordinate)
                .collect(java.util.stream.Collectors.toSet());
        skills.stream()
                .filter(skill -> skill.userId().equals(
                        secondaryUserId))
                .filter(skill -> primarySkillCoordinates.contains(
                        skill.coordinate()))
                .map(SkillRow::coordinate)
                .sorted()
                .forEach(coordinate -> conflicts.add(
                        new Conflict(
                                ConflictCode
                                        .SKILL_OWNERSHIP_CONFLICT,
                                coordinate)));

        List<SocialRow> stars = socialRows(
                "skill_star",
                primaryUserId,
                secondaryUserId,
                false);
        digest.rows("star", stars);
        List<SocialRow> ratings = socialRows(
                "skill_rating",
                primaryUserId,
                secondaryUserId,
                true);
        digest.rows("rating", ratings);
        List<SocialRow> subscriptions = socialRows(
                "skill_subscription",
                primaryUserId,
                secondaryUserId,
                false);
        digest.rows("subscription", subscriptions);
        SocialSummary social = new SocialSummary(
                movedCount(stars, primaryUserId, secondaryUserId),
                duplicateCount(
                        stars,
                        primaryUserId,
                        secondaryUserId),
                movedCount(
                        ratings,
                        primaryUserId,
                        secondaryUserId),
                duplicateCount(
                        ratings,
                        primaryUserId,
                        secondaryUserId),
                movedCount(
                        subscriptions,
                        primaryUserId,
                        secondaryUserId),
                duplicateCount(
                        subscriptions,
                        primaryUserId,
                        secondaryUserId),
                discardedRatings(
                        ratings,
                        primaryUserId,
                        secondaryUserId));

        List<WorkflowRow> pendingProfiles =
                pendingProfileChanges(secondaryUserId);
        digest.rows("profile-change", pendingProfiles);
        pendingProfiles.forEach(change -> conflicts.add(
                new Conflict(
                        ConflictCode.PENDING_PROFILE_CHANGE,
                        "profile-change")));

        List<TransientRow> passwordResets =
                passwordResets(secondaryUserId);
        digest.rows("password-reset", passwordResets);

        List<TransientRow> notifications =
                notifications(secondaryUserId);
        digest.rows("notification", notifications);
        List<PreferenceRow> preferences = preferences(
                primaryUserId,
                secondaryUserId);
        digest.rows("notification-preference", preferences);
        List<TransientRow> governanceNotifications =
                governanceNotifications(secondaryUserId);
        digest.rows(
                "governance-notification",
                governanceNotifications);
        int duplicatePreferences = duplicatePreferences(
                preferences,
                primaryUserId,
                secondaryUserId);
        int secondaryPreferences = (int) preferences.stream()
                .filter(row -> row.userId().equals(
                        secondaryUserId))
                .count();
        NotificationSummary notificationSummary =
                new NotificationSummary(
                        notifications.size(),
                        secondaryPreferences
                                - duplicatePreferences,
                        duplicatePreferences,
                        governanceNotifications.size());

        conflicts.sort(Comparator
                .comparing((Conflict conflict) ->
                        conflict.code().name())
                .thenComparing(Conflict::resource));
        return new AccountMergePlan(
                digest.finish(),
                secondaryProviders.stream().sorted().toList(),
                credentialAction,
                blockedRoles,
                namespaceChanges,
                tokenViews,
                (int) skills.stream()
                        .filter(skill -> skill.userId().equals(
                                secondaryUserId))
                        .count(),
                social,
                notificationSummary,
                conflicts);
    }

    @Override
    public void apply(
            String primaryUserId,
            String secondaryUserId,
            UUID intentId,
            AccountMergePlan plan,
            Instant now) {
        if (!plan.confirmable()) {
            throw new IllegalArgumentException(
                    "Blocked account merge plan cannot be applied");
        }
        Timestamp timestamp = Timestamp.from(now);
        moveBindings(primaryUserId, secondaryUserId, timestamp);
        moveCredential(
                primaryUserId,
                secondaryUserId,
                plan.localCredentialAction(),
                timestamp);
        moveMemberships(
                primaryUserId,
                secondaryUserId,
                plan.namespaceChanges(),
                timestamp);
        moveSkills(primaryUserId, secondaryUserId, timestamp);
        moveSocialState(
                "skill_star",
                "star_count",
                primaryUserId,
                secondaryUserId);
        moveRatings(primaryUserId, secondaryUserId);
        moveSocialState(
                "skill_subscription",
                "subscription_count",
                primaryUserId,
                secondaryUserId);
        revokeTokens(secondaryUserId, timestamp);
        consumePasswordResets(secondaryUserId, timestamp);
        moveNotifications(primaryUserId, secondaryUserId);
        moveNotificationPreferences(
                primaryUserId,
                secondaryUserId);
        moveGovernanceNotifications(
                primaryUserId,
                secondaryUserId);
        enqueueSessionRevocation(
                secondaryUserId,
                intentId,
                timestamp);
    }

    private List<AccountRow> accounts(
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT
                    id,
                    status,
                    merged_to_user_id,
                    system_account,
                    updated_at
                FROM user_account
                WHERE id IN (?, ?)
                ORDER BY id
                """,
                (result, rowNumber) -> new AccountRow(
                        result.getString("id"),
                        result.getString("status"),
                        result.getString("merged_to_user_id"),
                        result.getBoolean("system_account"),
                        result.getTimestamp("updated_at")),
                primaryUserId,
                secondaryUserId);
    }

    private List<BindingRow> bindings(
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT
                    id,
                    user_id,
                    provider_code,
                    status,
                    updated_at
                FROM identity_binding
                WHERE user_id IN (?, ?)
                  AND status = 'ACTIVE'
                ORDER BY user_id, provider_code, id
                """,
                (result, rowNumber) -> new BindingRow(
                        result.getLong("id"),
                        result.getString("user_id"),
                        result.getString("provider_code"),
                        result.getString("status"),
                        result.getTimestamp("updated_at")),
                primaryUserId,
                secondaryUserId);
    }

    private Set<String> providers(
            List<BindingRow> bindings,
            String userId) {
        LinkedHashSet<String> providers = new LinkedHashSet<>();
        bindings.stream()
                .filter(row -> row.userId().equals(userId))
                .map(BindingRow::providerCode)
                .sorted()
                .forEach(providers::add);
        return Set.copyOf(providers);
    }

    private List<CredentialRow> credentials(
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT
                    id,
                    user_id,
                    username,
                    failed_attempts,
                    locked_until,
                    updated_at
                FROM local_credential
                WHERE user_id IN (?, ?)
                ORDER BY user_id, id
                """,
                (result, rowNumber) -> new CredentialRow(
                        result.getLong("id"),
                        result.getString("user_id"),
                        result.getString("username"),
                        result.getInt("failed_attempts"),
                        result.getTimestamp("locked_until"),
                        result.getTimestamp("updated_at")),
                primaryUserId,
                secondaryUserId);
    }

    private LocalCredentialAction localCredentialAction(
            boolean primary,
            boolean secondary) {
        if (!secondary) {
            return LocalCredentialAction.NONE;
        }
        if (!primary) {
            return LocalCredentialAction.MOVE_SECONDARY;
        }
        return LocalCredentialAction
                .KEEP_PRIMARY_DELETE_SECONDARY;
    }

    private List<RoleRow> roles(
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT binding.id, binding.user_id, role.code
                FROM user_role_binding binding
                JOIN role ON role.id = binding.role_id
                WHERE binding.user_id IN (?, ?)
                ORDER BY binding.user_id, role.code, binding.id
                """,
                (result, rowNumber) -> new RoleRow(
                        result.getLong("id"),
                        result.getString("user_id"),
                        result.getString("code")),
                primaryUserId,
                secondaryUserId);
    }

    private List<WorkflowRow> activeIdentityLinks(
            String primaryUserId,
            String secondaryUserId,
            Instant now) {
        return jdbcTemplate.query("""
                SELECT
                    id,
                    primary_user_id,
                    provider_code,
                    status,
                    expires_at,
                    updated_at
                FROM identity_link_request
                WHERE primary_user_id IN (?, ?)
                  AND status IN (
                      'PENDING_REAUTHENTICATION',
                      'READY'
                  )
                  AND expires_at > ?
                ORDER BY primary_user_id, provider_code, id
                """,
                this::workflowRow,
                primaryUserId,
                secondaryUserId,
                Timestamp.from(now));
    }

    private List<MembershipRow> memberships(
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT
                    member.id,
                    member.user_id,
                    member.namespace_id,
                    namespace.slug,
                    member.role,
                    member.updated_at
                FROM namespace_member member
                JOIN namespace
                  ON namespace.id = member.namespace_id
                WHERE member.user_id IN (?, ?)
                ORDER BY
                    member.namespace_id,
                    member.user_id,
                    member.id
                """,
                (result, rowNumber) -> new MembershipRow(
                        result.getLong("id"),
                        result.getString("user_id"),
                        result.getLong("namespace_id"),
                        result.getString("slug"),
                        result.getString("role"),
                        result.getTimestamp("updated_at")),
                primaryUserId,
                secondaryUserId);
    }

    private List<NamespaceChange> namespaceChanges(
            List<MembershipRow> rows,
            String primaryUserId,
            String secondaryUserId,
            List<Conflict> conflicts) {
        Map<Long, MembershipPair> byNamespace =
                new LinkedHashMap<>();
        for (MembershipRow row : rows) {
            MembershipPair pair = byNamespace.computeIfAbsent(
                    row.namespaceId(),
                    ignored -> new MembershipPair(
                            row.namespaceId(),
                            row.namespaceSlug()));
            if (row.userId().equals(primaryUserId)) {
                pair.primary = row;
            } else if (row.userId().equals(
                    secondaryUserId)) {
                pair.secondary = row;
            }
        }
        List<NamespaceChange> changes = new ArrayList<>();
        for (MembershipPair pair : byNamespace.values()) {
            if (pair.secondary == null) {
                continue;
            }
            String primaryRole = pair.primary == null
                    ? null
                    : pair.primary.role();
            String secondaryRole = pair.secondary.role();
            String resultRole = strongerRole(
                    primaryRole,
                    secondaryRole);
            boolean blocked = "OWNER".equals(resultRole)
                    && !"OWNER".equals(primaryRole);
            if (blocked) {
                conflicts.add(new Conflict(
                        ConflictCode.NAMESPACE_OWNER_CONFLICT,
                        pair.namespaceSlug));
            }
            changes.add(new NamespaceChange(
                    pair.namespaceId,
                    pair.namespaceSlug,
                    primaryRole,
                    secondaryRole,
                    resultRole,
                    blocked));
        }
        return List.copyOf(changes);
    }

    private String strongerRole(
            String first,
            String second) {
        if (first == null) {
            return second;
        }
        return roleRank(first) >= roleRank(second)
                ? first
                : second;
    }

    private int roleRank(String role) {
        return switch (role) {
            case "OWNER" -> 3;
            case "ADMIN" -> 2;
            case "MEMBER" -> 1;
            default -> throw new IllegalStateException(
                    "Unknown namespace role " + role);
        };
    }

    private List<TokenRow> unrevokedTokens(
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT
                    id,
                    name,
                    token_prefix,
                    expires_at,
                    created_at
                FROM api_token
                WHERE user_id = ?
                  AND revoked_at IS NULL
                ORDER BY name, id
                """,
                (result, rowNumber) -> new TokenRow(
                        result.getLong("id"),
                        result.getString("name"),
                        result.getString("token_prefix"),
                        result.getTimestamp("expires_at"),
                        result.getTimestamp("created_at")),
                secondaryUserId);
    }

    private List<SkillRow> ownedSkills(
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT
                    id,
                    owner_id,
                    namespace_id,
                    slug,
                    updated_at
                FROM skill
                WHERE owner_id IN (?, ?)
                ORDER BY namespace_id, slug, owner_id, id
                """,
                (result, rowNumber) -> new SkillRow(
                        result.getLong("id"),
                        result.getString("owner_id"),
                        result.getLong("namespace_id"),
                        result.getString("slug"),
                        result.getTimestamp("updated_at")),
                primaryUserId,
                secondaryUserId);
    }

    private List<SocialRow> socialRows(
            String table,
            String primaryUserId,
            String secondaryUserId,
            boolean rating) {
        String valueColumn = rating
                ? ", score"
                : ", NULL AS score";
        String updatedColumn = rating
                ? ", updated_at"
                : ", created_at AS updated_at";
        String sql = """
                SELECT id, user_id, skill_id
                """
                + valueColumn
                + updatedColumn
                + " FROM "
                + table
                + """
                 WHERE user_id IN (?, ?)
                 ORDER BY skill_id, user_id, id
                """;
        return jdbcTemplate.query(
                sql,
                (result, rowNumber) -> new SocialRow(
                        result.getLong("id"),
                        result.getString("user_id"),
                        result.getLong("skill_id"),
                        nullableInteger(
                                result.getObject("score")),
                        result.getTimestamp("updated_at")),
                primaryUserId,
                secondaryUserId);
    }

    private Integer nullableInteger(Object value) {
        return value == null
                ? null
                : ((Number) value).intValue();
    }

    private int duplicateCount(
            List<SocialRow> rows,
            String primaryUserId,
            String secondaryUserId) {
        Set<Long> primarySkills = rows.stream()
                .filter(row -> row.userId().equals(
                        primaryUserId))
                .map(SocialRow::skillId)
                .collect(java.util.stream.Collectors.toSet());
        return (int) rows.stream()
                .filter(row -> row.userId().equals(
                        secondaryUserId))
                .filter(row -> primarySkills.contains(
                        row.skillId()))
                .count();
    }

    private int movedCount(
            List<SocialRow> rows,
            String primaryUserId,
            String secondaryUserId) {
        int secondary = (int) rows.stream()
                .filter(row -> row.userId().equals(
                        secondaryUserId))
                .count();
        return secondary - duplicateCount(
                rows,
                primaryUserId,
                secondaryUserId);
    }

    private List<DiscardedRating> discardedRatings(
            List<SocialRow> ratings,
            String primaryUserId,
            String secondaryUserId) {
        Set<Long> primarySkills = ratings.stream()
                .filter(row -> row.userId().equals(
                        primaryUserId))
                .map(SocialRow::skillId)
                .collect(java.util.stream.Collectors.toSet());
        return ratings.stream()
                .filter(row -> row.userId().equals(
                        secondaryUserId))
                .filter(row -> primarySkills.contains(
                        row.skillId()))
                .map(row -> new DiscardedRating(
                        row.skillId(),
                        java.util.Objects.requireNonNull(
                                row.score(),
                                "rating score")))
                .sorted(java.util.Comparator.comparingLong(
                        DiscardedRating::skillId))
                .toList();
    }

    private List<WorkflowRow> pendingProfileChanges(
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT
                    id,
                    user_id,
                    'profile' AS provider_code,
                    status,
                    created_at AS expires_at,
                    created_at AS updated_at
                FROM profile_change_request
                WHERE user_id = ?
                  AND status = 'PENDING'
                ORDER BY id
                """,
                this::workflowRow,
                secondaryUserId);
    }

    private List<TransientRow> passwordResets(
            String secondaryUserId) {
        return transientRows(
                """
                SELECT id, created_at
                FROM password_reset_request
                WHERE user_id = ?
                  AND consumed_at IS NULL
                ORDER BY id
                """,
                secondaryUserId);
    }

    private List<TransientRow> notifications(
            String secondaryUserId) {
        return transientRows(
                """
                SELECT id, created_at
                FROM notification
                WHERE recipient_id = ?
                ORDER BY id
                """,
                secondaryUserId);
    }

    private List<PreferenceRow> preferences(
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query("""
                SELECT id, user_id, category, channel, enabled
                FROM notification_preference
                WHERE user_id IN (?, ?)
                ORDER BY category, channel, user_id, id
                """,
                (result, rowNumber) -> new PreferenceRow(
                        result.getLong("id"),
                        result.getString("user_id"),
                        result.getString("category"),
                        result.getString("channel"),
                        result.getBoolean("enabled")),
                primaryUserId,
                secondaryUserId);
    }

    private int duplicatePreferences(
            List<PreferenceRow> preferences,
            String primaryUserId,
            String secondaryUserId) {
        Set<String> primary = preferences.stream()
                .filter(row -> row.userId().equals(
                        primaryUserId))
                .map(row -> row.category()
                        + "\u0000"
                        + row.channel())
                .collect(java.util.stream.Collectors.toSet());
        return (int) preferences.stream()
                .filter(row -> row.userId().equals(
                        secondaryUserId))
                .filter(row -> primary.contains(
                        row.category()
                                + "\u0000"
                                + row.channel()))
                .count();
    }

    private List<TransientRow> governanceNotifications(
            String secondaryUserId) {
        return transientRows(
                """
                SELECT id, created_at
                FROM user_notification
                WHERE user_id = ?
                ORDER BY id
                """,
                secondaryUserId);
    }

    private List<TransientRow> transientRows(
            String sql,
            String userId) {
        return jdbcTemplate.query(
                sql,
                (result, rowNumber) -> new TransientRow(
                        result.getLong("id"),
                        result.getTimestamp("created_at")),
                userId);
    }

    private WorkflowRow workflowRow(
            ResultSet result,
            int rowNumber) throws SQLException {
        return new WorkflowRow(
                result.getString("id"),
                result.getString(2),
                result.getString("provider_code"),
                result.getString("status"),
                result.getTimestamp("expires_at"),
                result.getTimestamp("updated_at"));
    }

    private void moveBindings(
            String primaryUserId,
            String secondaryUserId,
            Timestamp now) {
        jdbcTemplate.update("""
                UPDATE identity_binding
                SET user_id = ?, updated_at = ?
                WHERE user_id = ?
                  AND status = 'ACTIVE'
                """,
                primaryUserId,
                now,
                secondaryUserId);
    }

    private void moveCredential(
            String primaryUserId,
            String secondaryUserId,
            LocalCredentialAction action,
            Timestamp now) {
        switch (action) {
            case NONE -> {
            }
            case MOVE_SECONDARY -> jdbcTemplate.update("""
                    UPDATE local_credential
                    SET user_id = ?, updated_at = ?
                    WHERE user_id = ?
                    """,
                    primaryUserId,
                    now,
                    secondaryUserId);
            case KEEP_PRIMARY_DELETE_SECONDARY ->
                    jdbcTemplate.update("""
                            DELETE FROM local_credential
                            WHERE user_id = ?
                            """,
                            secondaryUserId);
        }
    }

    private void moveMemberships(
            String primaryUserId,
            String secondaryUserId,
            List<NamespaceChange> changes,
            Timestamp now) {
        for (NamespaceChange change : changes) {
            if (change.blocked()) {
                throw new IllegalArgumentException(
                        "Blocked namespace change cannot be applied");
            }
            if (change.primaryRole() == null) {
                jdbcTemplate.update("""
                        UPDATE namespace_member
                        SET user_id = ?, updated_at = ?
                        WHERE namespace_id = ?
                          AND user_id = ?
                        """,
                        primaryUserId,
                        now,
                        change.namespaceId(),
                        secondaryUserId);
                continue;
            }
            jdbcTemplate.update("""
                    UPDATE namespace_member
                    SET role = ?, updated_at = ?
                    WHERE namespace_id = ?
                      AND user_id = ?
                    """,
                    change.resultingRole(),
                    now,
                    change.namespaceId(),
                    primaryUserId);
            jdbcTemplate.update("""
                    DELETE FROM namespace_member
                    WHERE namespace_id = ?
                      AND user_id = ?
                    """,
                    change.namespaceId(),
                    secondaryUserId);
        }
    }

    private void moveSkills(
            String primaryUserId,
            String secondaryUserId,
            Timestamp now) {
        jdbcTemplate.update("""
                UPDATE skill_search_document
                SET owner_id = ?, updated_at = ?
                WHERE owner_id = ?
                """,
                primaryUserId,
                now,
                secondaryUserId);
        jdbcTemplate.update("""
                UPDATE skill
                SET owner_id = ?, updated_at = ?
                WHERE owner_id = ?
                """,
                primaryUserId,
                now,
                secondaryUserId);
    }

    private void moveSocialState(
            String table,
            String counterColumn,
            String primaryUserId,
            String secondaryUserId) {
        List<Long> affected = affectedSkills(
                table,
                primaryUserId,
                secondaryUserId);
        String deleteSql = "DELETE FROM "
                + table
                + " secondary_state WHERE secondary_state.user_id = ?"
                + " AND EXISTS (SELECT 1 FROM "
                + table
                + " primary_state WHERE primary_state.skill_id"
                + " = secondary_state.skill_id"
                + " AND primary_state.user_id = ?)";
        jdbcTemplate.update(
                deleteSql,
                secondaryUserId,
                primaryUserId);
        jdbcTemplate.update(
                "UPDATE " + table
                        + " SET user_id = ? WHERE user_id = ?",
                primaryUserId,
                secondaryUserId);
        for (Long skillId : affected) {
            jdbcTemplate.update(
                    "UPDATE skill SET "
                            + counterColumn
                            + " = (SELECT COUNT(*) FROM "
                            + table
                            + " WHERE skill_id = ?)"
                            + " WHERE id = ?",
                    skillId,
                    skillId);
        }
    }

    private void moveRatings(
            String primaryUserId,
            String secondaryUserId) {
        List<Long> affected = affectedSkills(
                "skill_rating",
                primaryUserId,
                secondaryUserId);
        jdbcTemplate.update("""
                DELETE FROM skill_rating secondary_rating
                WHERE secondary_rating.user_id = ?
                  AND EXISTS (
                      SELECT 1
                      FROM skill_rating primary_rating
                      WHERE primary_rating.skill_id =
                            secondary_rating.skill_id
                        AND primary_rating.user_id = ?
                  )
                """,
                secondaryUserId,
                primaryUserId);
        jdbcTemplate.update("""
                UPDATE skill_rating
                SET user_id = ?
                WHERE user_id = ?
                """,
                primaryUserId,
                secondaryUserId);
        for (Long skillId : affected) {
            jdbcTemplate.update("""
                    UPDATE skill
                    SET
                        rating_count = (
                            SELECT COUNT(*)
                            FROM skill_rating
                            WHERE skill_id = ?
                        ),
                        rating_avg = COALESCE((
                            SELECT AVG(score)
                            FROM skill_rating
                            WHERE skill_id = ?
                        ), 0)
                    WHERE id = ?
                    """,
                    skillId,
                    skillId,
                    skillId);
        }
    }

    private List<Long> affectedSkills(
            String table,
            String primaryUserId,
            String secondaryUserId) {
        return jdbcTemplate.query(
                "SELECT DISTINCT skill_id FROM "
                        + table
                        + " WHERE user_id IN (?, ?)"
                        + " ORDER BY skill_id",
                (result, rowNumber) ->
                        result.getLong("skill_id"),
                primaryUserId,
                secondaryUserId);
    }

    private void revokeTokens(
            String secondaryUserId,
            Timestamp now) {
        jdbcTemplate.update("""
                UPDATE api_token
                SET revoked_at = ?
                WHERE user_id = ?
                  AND revoked_at IS NULL
                """,
                now,
                secondaryUserId);
    }

    private void consumePasswordResets(
            String secondaryUserId,
            Timestamp now) {
        jdbcTemplate.update("""
                UPDATE password_reset_request
                SET consumed_at = ?
                WHERE user_id = ?
                  AND consumed_at IS NULL
                """,
                now,
                secondaryUserId);
    }

    private void moveNotifications(
            String primaryUserId,
            String secondaryUserId) {
        jdbcTemplate.update("""
                UPDATE notification
                SET recipient_id = ?
                WHERE recipient_id = ?
                """,
                primaryUserId,
                secondaryUserId);
    }

    private void moveNotificationPreferences(
            String primaryUserId,
            String secondaryUserId) {
        jdbcTemplate.update("""
                DELETE FROM notification_preference secondary_pref
                WHERE secondary_pref.user_id = ?
                  AND EXISTS (
                      SELECT 1
                      FROM notification_preference primary_pref
                      WHERE primary_pref.user_id = ?
                        AND primary_pref.category =
                            secondary_pref.category
                        AND primary_pref.channel =
                            secondary_pref.channel
                  )
                """,
                secondaryUserId,
                primaryUserId);
        jdbcTemplate.update("""
                UPDATE notification_preference
                SET user_id = ?
                WHERE user_id = ?
                """,
                primaryUserId,
                secondaryUserId);
    }

    private void moveGovernanceNotifications(
            String primaryUserId,
            String secondaryUserId) {
        jdbcTemplate.update("""
                UPDATE user_notification
                SET user_id = ?
                WHERE user_id = ?
                """,
                primaryUserId,
                secondaryUserId);
    }

    private void enqueueSessionRevocation(
            String secondaryUserId,
            UUID intentId,
            Timestamp now) {
        jdbcTemplate.update("""
                INSERT INTO account_merge_session_revocation (
                    merge_intent_id,
                    user_id,
                    status,
                    attempt_count,
                    next_attempt_at,
                    created_at,
                    updated_at
                ) VALUES (?, ?, 'PENDING', 0, ?, ?, ?)
                """,
                intentId,
                secondaryUserId,
                now,
                now,
                now);
    }

    private record AccountRow(
            String id,
            String status,
            String mergedToUserId,
            boolean systemAccount,
            Timestamp updatedAt) {
    }

    private record BindingRow(
            long id,
            String userId,
            String providerCode,
            String status,
            Timestamp updatedAt) {
    }

    private record CredentialRow(
            long id,
            String userId,
            String username,
            int failedAttempts,
            Timestamp lockedUntil,
            Timestamp updatedAt) {
    }

    private record RoleRow(
            long id,
            String userId,
            String roleCode) {
    }

    private record WorkflowRow(
            String id,
            String userId,
            String providerCode,
            String status,
            Timestamp expiresAt,
            Timestamp updatedAt) {
    }

    private record MembershipRow(
            long id,
            String userId,
            long namespaceId,
            String namespaceSlug,
            String role,
            Timestamp updatedAt) {
    }

    private record TokenRow(
            long id,
            String name,
            String prefix,
            Timestamp expiresAt,
            Timestamp createdAt) {
    }

    private record SkillRow(
            long id,
            String userId,
            long namespaceId,
            String slug,
            Timestamp updatedAt) {

        private String coordinate() {
            return namespaceId + "/" + slug;
        }
    }

    private record SocialRow(
            long id,
            String userId,
            long skillId,
            Integer score,
            Timestamp updatedAt) {
    }

    private record TransientRow(
            long id,
            Timestamp createdAt) {
    }

    private record PreferenceRow(
            long id,
            String userId,
            String category,
            String channel,
            boolean enabled) {
    }

    private static final class MembershipPair {
        private final long namespaceId;
        private final String namespaceSlug;
        private MembershipRow primary;
        private MembershipRow secondary;

        private MembershipPair(
                long namespaceId,
                String namespaceSlug) {
            this.namespaceId = namespaceId;
            this.namespaceSlug = namespaceSlug;
        }
    }

    private static final class SnapshotDigest {
        private final MessageDigest digest;

        private SnapshotDigest() {
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(
                        "SHA-256 is unavailable",
                        exception);
            }
        }

        private void rows(String section, List<?> rows) {
            value(section);
            value(rows.size());
            rows.forEach(this::value);
        }

        private void value(Object value) {
            String text = value == null
                    ? "<null>"
                    : value.toString();
            byte[] bytes = text.getBytes(
                    StandardCharsets.UTF_8);
            digest.update(Integer.toString(bytes.length)
                    .getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) ':');
            digest.update(bytes);
            digest.update((byte) '\n');
        }

        private String finish() {
            return HexFormat.of().formatHex(digest.digest());
        }
    }
}
