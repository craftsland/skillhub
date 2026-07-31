package com.iflytek.skillhub.auth.identity;

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
 * Owns the raw, high-entropy session state used by Identity Link workflows.
 *
 * <p>Only a SHA-256 digest is stored outside the session. Raw nonces and
 * browser-protocol state values are never returned by API DTOs or written to
 * the database.
 */
@Component
public class IdentityLinkSessionManager {

    private static final String NONCE_ATTRIBUTE_PREFIX =
            "skillhub.identityLink.nonce.";
    private static final String PENDING_BROWSER_FLOW_ATTRIBUTE =
            "skillhub.identityLink.browser.pending";
    private static final String ACTIVE_BROWSER_FLOW_ATTRIBUTE =
            "skillhub.identityLink.browser.active";
    private static final Duration BROWSER_FLOW_TTL =
            Duration.ofMinutes(5);

    private final SecureRandom secureRandom;
    private final IdentityLinkStateHasher stateHasher;
    private final Clock clock;

    @Autowired
    public IdentityLinkSessionManager(
            IdentityLinkStateHasher stateHasher,
            Clock clock) {
        this(
                new SecureRandom(),
                stateHasher,
                clock);
    }

    IdentityLinkSessionManager(
            SecureRandom secureRandom,
            IdentityLinkStateHasher stateHasher,
            Clock clock) {
        this.secureRandom = secureRandom;
        this.stateHasher = stateHasher;
        this.clock = clock;
    }

    public IdentityLinkActor start(
            HttpSession session,
            UUID intentId,
            IdentityLoginContext context) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(intentId, "intentId");
        byte[] nonceBytes = new byte[32];
        secureRandom.nextBytes(nonceBytes);
        String nonce = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(nonceBytes);
        session.setAttribute(
                nonceAttribute(intentId),
                nonce);
        return actor(session, intentId, context);
    }

    public IdentityLinkActor actor(
            HttpSession session,
            UUID intentId,
            IdentityLoginContext context) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(intentId, "intentId");
        Object principalValue =
                session.getAttribute("platformPrincipal");
        if (!(principalValue instanceof PlatformPrincipal principal)) {
            throw new IdentityLinkException(
                    IdentityLinkFailureCode.SESSION_MISMATCH);
        }
        Object nonceValue = session.getAttribute(
                nonceAttribute(intentId));
        if (!(nonceValue instanceof String nonce)
                || nonce.isBlank()) {
            throw new IdentityLinkException(
                    IdentityLinkFailureCode.SESSION_MISMATCH);
        }
        String authenticationProvider =
                principal.oauthProvider() == null
                        || principal.oauthProvider().isBlank()
                        ? "session"
                        : principal.oauthProvider();
        return new IdentityLinkActor(
                principal.userId(),
                authenticationProvider,
                nonce,
                context);
    }

    public void remove(HttpSession session, UUID intentId) {
        if (session == null || intentId == null) {
            return;
        }
        session.removeAttribute(nonceAttribute(intentId));
        clearBrowserFlowForIntent(session, intentId);
    }

    public void prepareBrowserFlow(
            HttpSession session,
            UUID intentId,
            IdentityLinkBrowserPhase phase,
            String providerCode,
            IdentityLoginContext context) {
        actor(session, intentId, context);
        PendingBrowserFlow pending = new PendingBrowserFlow(
                intentId,
                Objects.requireNonNull(phase, "phase"),
                requireProviderCode(providerCode),
                now().plus(BROWSER_FLOW_TTL));
        session.setAttribute(
                PENDING_BROWSER_FLOW_ATTRIBUTE,
                pending);
        session.removeAttribute(ACTIVE_BROWSER_FLOW_ATTRIBUTE);
    }

    /**
     * Binds a prepared link flow to the browser protocol's authorization
     * request. OAuth keeps the raw state in Spring Security and CAS keeps it
     * in the CAS state store; only its digest is copied here.
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
                || pending.expiresAt().isBefore(now())
                || !pending.providerCode().equals(providerCode)
                || browserState == null
                || browserState.isBlank()) {
            return;
        }
        session.setAttribute(
                ACTIVE_BROWSER_FLOW_ATTRIBUTE,
                new ActiveBrowserFlow(
                        pending.intentId(),
                        pending.phase(),
                        pending.providerCode(),
                        stateHasher.hash(browserState),
                        pending.expiresAt()));
    }

    public Optional<IdentityLinkBrowserFlow> consumeBrowserFlow(
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
        if (active.expiresAt().isBefore(now())
                || !active.providerCode().equals(providerCode)
                || !stateHasher.matches(
                        callbackState,
                        active.browserStateHash())) {
            throw new IdentityLinkException(
                    IdentityLinkFailureCode.SESSION_MISMATCH);
        }
        return Optional.of(new IdentityLinkBrowserFlow(
                active.intentId(),
                active.phase(),
                actor(
                        session,
                        active.intentId(),
                        context)));
    }

    public void clearBrowserFlow(HttpSession session) {
        if (session == null) {
            return;
        }
        session.removeAttribute(PENDING_BROWSER_FLOW_ATTRIBUTE);
        session.removeAttribute(ACTIVE_BROWSER_FLOW_ATTRIBUTE);
    }

    /**
     * Clears a failed browser flow while retaining the session-bound intent
     * nonce so the account-security UI can safely resume or cancel it.
     */
    public Optional<UUID> consumeFailedBrowserFlow(
            HttpSession session) {
        if (session == null) {
            return Optional.empty();
        }
        Object active = session.getAttribute(
                ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        Object pending = session.getAttribute(
                PENDING_BROWSER_FLOW_ATTRIBUTE);
        clearBrowserFlow(session);
        if (active instanceof ActiveBrowserFlow flow) {
            return Optional.of(flow.intentId());
        }
        if (pending instanceof PendingBrowserFlow flow) {
            return Optional.of(flow.intentId());
        }
        return Optional.empty();
    }

    private void clearBrowserFlowForIntent(
            HttpSession session,
            UUID intentId) {
        Object pending = session.getAttribute(
                PENDING_BROWSER_FLOW_ATTRIBUTE);
        if (pending instanceof PendingBrowserFlow flow
                && flow.intentId().equals(intentId)) {
            session.removeAttribute(
                    PENDING_BROWSER_FLOW_ATTRIBUTE);
        }
        Object active = session.getAttribute(
                ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        if (active instanceof ActiveBrowserFlow flow
                && flow.intentId().equals(intentId)) {
            session.removeAttribute(
                    ACTIVE_BROWSER_FLOW_ATTRIBUTE);
        }
    }

    private String nonceAttribute(UUID intentId) {
        return NONCE_ATTRIBUTE_PREFIX + intentId;
    }

    private String requireProviderCode(String providerCode) {
        if (providerCode == null
                || providerCode.isBlank()
                || providerCode.length() > 64) {
            throw new IdentityLinkException(
                    IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
        }
        return providerCode;
    }

    private Instant now() {
        return Instant.now(clock);
    }

    private record PendingBrowserFlow(
            UUID intentId,
            IdentityLinkBrowserPhase phase,
            String providerCode,
            Instant expiresAt
    ) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }

    private record ActiveBrowserFlow(
            UUID intentId,
            IdentityLinkBrowserPhase phase,
            String providerCode,
            String browserStateHash,
            Instant expiresAt
    ) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }
}
