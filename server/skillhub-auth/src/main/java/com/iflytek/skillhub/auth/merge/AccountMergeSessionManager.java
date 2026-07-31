package com.iflytek.skillhub.auth.merge;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.Serial;
import java.io.Serializable;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Owns raw, high-entropy Session state for safe account-merge workflows.
 *
 * <p>A fresh primary proof is stored only in the current Platform Session and
 * consumed once when an intent is created. The intent then receives a separate
 * Session nonce whose SHA-256 digest is persisted by the merge transaction.
 */
@Component
public class AccountMergeSessionManager {

    static final Duration PRIMARY_PROOF_TTL =
            Duration.ofMinutes(10);

    private static final String PRIMARY_PROOF_ATTRIBUTE =
            "skillhub.accountMerge.primaryProof";
    private static final String INTENT_ATTRIBUTE_PREFIX =
            "skillhub.accountMerge.intent.";
    private static final String PENDING_BROWSER_FLOW_ATTRIBUTE =
            "skillhub.accountMerge.browser.pending";
    private static final String ACTIVE_BROWSER_FLOW_ATTRIBUTE =
            "skillhub.accountMerge.browser.active";
    private static final Duration BROWSER_FLOW_TTL =
            Duration.ofMinutes(5);

    private final SecureRandom secureRandom;
    private final AccountMergeStateHasher stateHasher;
    private final Clock clock;

    @Autowired
    public AccountMergeSessionManager(
            AccountMergeStateHasher stateHasher,
            Clock clock) {
        this(new SecureRandom(), stateHasher, clock);
    }

    public AccountMergeSessionManager(Clock clock) {
        this(
                new SecureRandom(),
                new AccountMergeStateHasher(),
                clock);
    }

    AccountMergeSessionManager(
            SecureRandom secureRandom,
            Clock clock) {
        this(
                secureRandom,
                new AccountMergeStateHasher(),
                clock);
    }

    AccountMergeSessionManager(
            SecureRandom secureRandom,
            AccountMergeStateHasher stateHasher,
            Clock clock) {
        this.secureRandom = Objects.requireNonNull(
                secureRandom,
                "secureRandom");
        this.stateHasher = Objects.requireNonNull(
                stateHasher,
                "stateHasher");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public AccountMergePrimaryProof recordPrimaryReauthentication(
            HttpSession session,
            String userId,
            String method) {
        PlatformPrincipal principal = requirePrincipal(session);
        if (!principal.userId().equals(userId)) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        Instant authenticatedAt = now();
        Instant expiresAt =
                authenticatedAt.plus(PRIMARY_PROOF_TTL);
        PrimaryProofState proof = new PrimaryProofState(
                userId,
                requireText(method, "method", 96),
                randomSecret(),
                authenticatedAt,
                expiresAt);
        session.setAttribute(PRIMARY_PROOF_ATTRIBUTE, proof);
        return new AccountMergePrimaryProof(
                proof.method(),
                proof.authenticatedAt(),
                proof.expiresAt());
    }

    public AccountMergeActor startIntent(
            HttpSession session,
            UUID intentId,
            IdentityLoginContext context) {
        Objects.requireNonNull(intentId, "intentId");
        PlatformPrincipal principal = requirePrincipal(session);
        Object value = session.getAttribute(
                PRIMARY_PROOF_ATTRIBUTE);
        session.removeAttribute(PRIMARY_PROOF_ATTRIBUTE);
        if (!(value instanceof PrimaryProofState proof)) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_REAUTH_REQUIRED);
        }
        if (!proof.userId().equals(principal.userId())) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        if (!now().isBefore(proof.expiresAt())) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_PROOF_EXPIRED);
        }
        IntentSessionState intentState =
                new IntentSessionState(
                        principal.userId(),
                        authenticationProvider(principal),
                        randomSecret(),
                        proof.method(),
                        proof.authenticatedAt());
        session.setAttribute(
                intentAttribute(intentId),
                intentState);
        return actor(
                intentState,
                Objects.requireNonNull(context, "context"));
    }

    public AccountMergeActor actor(
            HttpSession session,
            UUID intentId,
            IdentityLoginContext context) {
        PlatformPrincipal principal = requirePrincipal(session);
        Object value = session.getAttribute(
                intentAttribute(
                        Objects.requireNonNull(
                                intentId,
                                "intentId")));
        if (!(value instanceof IntentSessionState state)
                || !state.userId().equals(principal.userId())) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        return actor(
                state,
                Objects.requireNonNull(context, "context"));
    }

    public void remove(HttpSession session, UUID intentId) {
        if (session == null || intentId == null) {
            return;
        }
        session.removeAttribute(intentAttribute(intentId));
        clearBrowserFlowForIntent(session, intentId);
    }

    public void preparePrimaryBrowserFlow(
            HttpSession session,
            String providerCode) {
        PlatformPrincipal principal = requirePrincipal(session);
        prepareBrowserFlow(
                session,
                new PendingBrowserFlow(
                        AccountMergeBrowserPhase
                                .PRIMARY_REAUTHENTICATION,
                        null,
                        principal.userId(),
                        requireText(
                                providerCode,
                                "providerCode",
                                64),
                        now().plus(BROWSER_FLOW_TTL)));
    }

    public void prepareSecondaryBrowserFlow(
            HttpSession session,
            UUID intentId,
            String providerCode,
            IdentityLoginContext context) {
        AccountMergeActor actor = actor(
                session,
                intentId,
                context);
        prepareBrowserFlow(
                session,
                new PendingBrowserFlow(
                        AccountMergeBrowserPhase
                                .SECONDARY_AUTHENTICATION,
                        intentId,
                        actor.userId(),
                        requireText(
                                providerCode,
                                "providerCode",
                                64),
                        now().plus(BROWSER_FLOW_TTL)));
    }

    /**
     * Binds the pending merge proof to OAuth/CAS raw browser state while
     * persisting only a digest in the session.
     */
    public void activateBrowserFlow(
            HttpSession session,
            String providerCode,
            String browserState) {
        if (session == null) {
            return;
        }
        Object value = session.getAttribute(
                PENDING_BROWSER_FLOW_ATTRIBUTE);
        session.removeAttribute(PENDING_BROWSER_FLOW_ATTRIBUTE);
        if (!(value instanceof PendingBrowserFlow pending)
                || !now().isBefore(pending.expiresAt())
                || !pending.providerCode().equals(providerCode)
                || browserState == null
                || browserState.isBlank()) {
            return;
        }
        session.setAttribute(
                ACTIVE_BROWSER_FLOW_ATTRIBUTE,
                new ActiveBrowserFlow(
                        pending.phase(),
                        pending.intentId(),
                        pending.primaryUserId(),
                        pending.providerCode(),
                        stateHasher.hash(browserState),
                        pending.expiresAt()));
    }

    public Optional<AccountMergeBrowserFlow> consumeBrowserFlow(
            HttpServletRequest request,
            String providerCode,
            IdentityLoginContext context) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Optional.empty();
        }
        Object value = session.getAttribute(
                ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        if (!(value instanceof ActiveBrowserFlow active)) {
            return Optional.empty();
        }
        session.removeAttribute(ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        String callbackState = request.getParameter("state");
        PlatformPrincipal principal = requirePrincipal(session);
        if (!now().isBefore(active.expiresAt())
                || !active.providerCode().equals(providerCode)
                || !active.primaryUserId().equals(
                        principal.userId())
                || !stateHasher.matches(
                        callbackState,
                        active.browserStateHash())) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        if (active.phase()
                == AccountMergeBrowserPhase
                        .PRIMARY_REAUTHENTICATION) {
            return Optional.of(
                    new AccountMergeBrowserFlow.Primary(
                            principal.userId(),
                            active.providerCode()));
        }
        UUID intentId = Objects.requireNonNull(
                active.intentId(),
                "intentId");
        return Optional.of(
                new AccountMergeBrowserFlow.Secondary(
                        intentId,
                        actor(session, intentId, context),
                        active.providerCode()));
    }

    public Optional<AccountMergeBrowserFlowReference>
            consumeFailedBrowserFlow(HttpSession session) {
        if (session == null) {
            return Optional.empty();
        }
        Object active = session.getAttribute(
                ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        Object pending = session.getAttribute(
                PENDING_BROWSER_FLOW_ATTRIBUTE);
        clearBrowserFlow(session);
        if (active instanceof ActiveBrowserFlow flow) {
            return Optional.of(
                    new AccountMergeBrowserFlowReference(
                            flow.phase(),
                            flow.intentId()));
        }
        if (pending instanceof PendingBrowserFlow flow) {
            return Optional.of(
                    new AccountMergeBrowserFlowReference(
                            flow.phase(),
                            flow.intentId()));
        }
        return Optional.empty();
    }

    public void clearBrowserFlow(HttpSession session) {
        if (session == null) {
            return;
        }
        session.removeAttribute(PENDING_BROWSER_FLOW_ATTRIBUTE);
        session.removeAttribute(ACTIVE_BROWSER_FLOW_ATTRIBUTE);
    }

    private void prepareBrowserFlow(
            HttpSession session,
            PendingBrowserFlow pending) {
        session.setAttribute(
                PENDING_BROWSER_FLOW_ATTRIBUTE,
                pending);
        session.removeAttribute(ACTIVE_BROWSER_FLOW_ATTRIBUTE);
    }

    private void clearBrowserFlowForIntent(
            HttpSession session,
            UUID intentId) {
        Object pending = session.getAttribute(
                PENDING_BROWSER_FLOW_ATTRIBUTE);
        if (pending instanceof PendingBrowserFlow flow
                && intentId.equals(flow.intentId())) {
            session.removeAttribute(
                    PENDING_BROWSER_FLOW_ATTRIBUTE);
        }
        Object active = session.getAttribute(
                ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        if (active instanceof ActiveBrowserFlow flow
                && intentId.equals(flow.intentId())) {
            session.removeAttribute(
                    ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        }
    }

    private AccountMergeActor actor(
            IntentSessionState state,
            IdentityLoginContext context) {
        return new AccountMergeActor(
                state.userId(),
                state.authenticationProvider(),
                state.sessionNonce(),
                state.primaryProofMethod(),
                state.primaryProofAt(),
                context);
    }

    private PlatformPrincipal requirePrincipal(
            HttpSession session) {
        Objects.requireNonNull(session, "session");
        Object value = session.getAttribute(
                "platformPrincipal");
        if (!(value instanceof PlatformPrincipal principal)) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        return principal;
    }

    private String authenticationProvider(
            PlatformPrincipal principal) {
        String provider = principal.oauthProvider();
        return provider == null || provider.isBlank()
                ? "session"
                : provider;
    }

    private String randomSecret() {
        byte[] value = new byte[32];
        secureRandom.nextBytes(value);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value);
    }

    private String intentAttribute(UUID intentId) {
        return INTENT_ATTRIBUTE_PREFIX + intentId;
    }

    private Instant now() {
        return Instant.now(clock);
    }

    private AccountMergeException failure(
            AccountMergeFailureCode code) {
        return new AccountMergeException(code);
    }

    private String requireText(
            String value,
            String fieldName,
            int maximumLength) {
        if (value == null
                || value.isBlank()
                || value.length() > maximumLength) {
            throw new IllegalArgumentException(
                    "Invalid account merge " + fieldName);
        }
        return value;
    }

    private record PrimaryProofState(
            String userId,
            String method,
            String rawProof,
            Instant authenticatedAt,
            Instant expiresAt
    ) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }

    private record IntentSessionState(
            String userId,
            String authenticationProvider,
            String sessionNonce,
            String primaryProofMethod,
            Instant primaryProofAt
    ) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }

    private record PendingBrowserFlow(
            AccountMergeBrowserPhase phase,
            UUID intentId,
            String primaryUserId,
            String providerCode,
            Instant expiresAt
    ) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }

    private record ActiveBrowserFlow(
            AccountMergeBrowserPhase phase,
            UUID intentId,
            String primaryUserId,
            String providerCode,
            String browserStateHash,
            Instant expiresAt
    ) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }
}
