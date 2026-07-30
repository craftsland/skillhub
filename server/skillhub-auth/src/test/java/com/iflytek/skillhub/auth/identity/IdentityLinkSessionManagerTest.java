package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

class IdentityLinkSessionManagerTest {

    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-07-31T08:00:00Z"),
            ZoneOffset.UTC);
    private static final IdentityLoginContext CONTEXT =
            new IdentityLoginContext(
                    "req-1",
                    "203.0.113.9",
                    "Browser");

    private IdentityLinkSessionManager manager;
    private MockHttpSession session;

    @BeforeEach
    void setUp() {
        manager = new IdentityLinkSessionManager(
                new SecureRandom(),
                new IdentityLinkStateHasher(),
                CLOCK);
        session = new MockHttpSession();
        session.setAttribute(
                "platformPrincipal",
                new PlatformPrincipal(
                        "usr_1",
                        "Alice",
                        "alice@example.com",
                        null,
                        "local",
                        Set.of("USER")));
    }

    @Test
    void generatedNonceStaysInSessionAndIsOmittedFromActorString() {
        UUID intentId = UUID.randomUUID();

        IdentityLinkActor actor = manager.start(
                session,
                intentId,
                CONTEXT);

        assertThat(actor.userId()).isEqualTo("usr_1");
        assertThat(actor.toString())
                .contains("usr_1")
                .doesNotContain("nonce");
        assertThat(manager.actor(session, intentId, CONTEXT).userId())
                .isEqualTo("usr_1");
    }

    @Test
    void anotherSessionCannotResumeIntent() {
        UUID intentId = UUID.randomUUID();
        manager.start(session, intentId, CONTEXT);
        MockHttpSession otherSession = new MockHttpSession();
        otherSession.setAttribute(
                "platformPrincipal",
                session.getAttribute("platformPrincipal"));

        assertThatThrownBy(() ->
                manager.actor(otherSession, intentId, CONTEXT))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .SESSION_MISMATCH));
    }

    @Test
    void browserFlowIsBoundToProviderOAuthStateAndConsumedOnce() {
        UUID intentId = UUID.randomUUID();
        manager.start(session, intentId, CONTEXT);
        manager.prepareBrowserFlow(
                session,
                intentId,
                IdentityLinkBrowserPhase.LINK,
                "github",
                CONTEXT);
        manager.activateBrowserFlow(
                session,
                "github",
                "oauth-state");
        MockHttpServletRequest callback =
                new MockHttpServletRequest(
                        "GET",
                        "/login/oauth2/code/github");
        callback.setSession(session);
        callback.setParameter("state", "oauth-state");

        IdentityLinkBrowserFlow flow =
                manager.consumeBrowserFlow(
                                callback,
                                "github",
                                CONTEXT)
                        .orElseThrow();

        assertThat(flow.intentId()).isEqualTo(intentId);
        assertThat(flow.phase())
                .isEqualTo(IdentityLinkBrowserPhase.LINK);
        assertThat(manager.consumeBrowserFlow(
                callback,
                "github",
                CONTEXT)).isEmpty();
    }

    @Test
    void mismatchedOAuthStateFailsClosedAndCannotBeRetried() {
        UUID intentId = UUID.randomUUID();
        manager.start(session, intentId, CONTEXT);
        manager.prepareBrowserFlow(
                session,
                intentId,
                IdentityLinkBrowserPhase.REAUTHENTICATE,
                "github",
                CONTEXT);
        manager.activateBrowserFlow(
                session,
                "github",
                "expected-state");
        MockHttpServletRequest callback =
                new MockHttpServletRequest(
                        "GET",
                        "/login/oauth2/code/github");
        callback.setSession(session);
        callback.setParameter("state", "different-state");

        assertThatThrownBy(() ->
                manager.consumeBrowserFlow(
                        callback,
                        "github",
                        CONTEXT))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .SESSION_MISMATCH));
        assertThat(manager.consumeBrowserFlow(
                callback,
                "github",
                CONTEXT)).isEmpty();
    }

    @Test
    void failedBrowserFlowKeepsIntentAndCanBeRetried() {
        UUID intentId = UUID.randomUUID();
        manager.start(session, intentId, CONTEXT);
        manager.prepareBrowserFlow(
                session,
                intentId,
                IdentityLinkBrowserPhase.LINK,
                "github",
                CONTEXT);
        manager.activateBrowserFlow(
                session,
                "github",
                "oauth-state");

        assertThat(manager.consumeFailedBrowserFlow(session))
                .contains(intentId);
        assertThat(manager.consumeFailedBrowserFlow(session))
                .isEmpty();
        assertThat(manager.actor(session, intentId, CONTEXT).userId())
                .isEqualTo("usr_1");

        manager.prepareBrowserFlow(
                session,
                intentId,
                IdentityLinkBrowserPhase.LINK,
                "github",
                CONTEXT);
        manager.activateBrowserFlow(
                session,
                "github",
                "retry-state");
        MockHttpServletRequest retryCallback =
                new MockHttpServletRequest(
                        "GET",
                        "/login/oauth2/code/github");
        retryCallback.setSession(session);
        retryCallback.setParameter("state", "retry-state");

        assertThat(manager.consumeBrowserFlow(
                        retryCallback,
                        "github",
                        CONTEXT))
                .map(IdentityLinkBrowserFlow::intentId)
                .contains(intentId);
    }
}
