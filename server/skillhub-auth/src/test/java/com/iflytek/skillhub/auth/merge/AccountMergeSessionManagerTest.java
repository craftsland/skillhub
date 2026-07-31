package com.iflytek.skillhub.auth.merge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
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

class AccountMergeSessionManagerTest {

    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-07-31T09:00:00Z"),
            ZoneOffset.UTC);
    private static final IdentityLoginContext CONTEXT =
            new IdentityLoginContext(
                    "req-merge-1",
                    "203.0.113.10",
                    "Browser");

    private AccountMergeSessionManager manager;
    private MockHttpSession session;

    @BeforeEach
    void setUp() {
        manager = new AccountMergeSessionManager(
                new SecureRandom(),
                CLOCK);
        session = new MockHttpSession();
        session.setAttribute(
                "platformPrincipal",
                new PlatformPrincipal(
                        "usr_primary",
                        "Primary",
                        "primary@example.com",
                        null,
                        "local",
                        Set.of("USER")));
    }

    @Test
    void creatingIntentWithoutFreshReauthenticationFailsClosed() {
        assertThatThrownBy(() -> manager.startIntent(
                session,
                UUID.randomUUID(),
                CONTEXT))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_REAUTH_REQUIRED));
    }

    @Test
    void freshLocalProofIsConsumedOnceAndRawValuesStayOutOfToString() {
        AccountMergePrimaryProof proof =
                manager.recordPrimaryReauthentication(
                        session,
                        "usr_primary",
                        "local-password");

        AccountMergeActor actor = manager.startIntent(
                session,
                UUID.randomUUID(),
                CONTEXT);

        assertThat(proof.authenticatedAt())
                .isEqualTo(Instant.parse("2026-07-31T09:00:00Z"));
        assertThat(proof.expiresAt())
                .isEqualTo(Instant.parse("2026-07-31T09:10:00Z"));
        assertThat(actor.userId()).isEqualTo("usr_primary");
        assertThat(actor.primaryProofMethod())
                .isEqualTo("local-password");
        assertThat(actor.toString())
                .contains("usr_primary")
                .doesNotContain("nonce")
                .doesNotContain("proof");

        assertThatThrownBy(() -> manager.startIntent(
                session,
                UUID.randomUUID(),
                CONTEXT))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_REAUTH_REQUIRED));
    }

    @Test
    void primaryBrowserProofIsBoundToStateAndConsumedOnce() {
        String state = "oauth-state-primary";
        manager.preparePrimaryBrowserFlow(session, "github");
        manager.activateBrowserFlow(
                session,
                "github",
                state);
        MockHttpServletRequest request =
                callbackRequest(state);

        AccountMergeBrowserFlow flow =
                manager.consumeBrowserFlow(
                                request,
                                "github",
                                CONTEXT)
                        .orElseThrow();

        assertThat(flow)
                .isInstanceOf(
                        AccountMergeBrowserFlow.Primary.class);
        assertThat(flow.primaryUserId())
                .isEqualTo("usr_primary");
        assertThat(manager.consumeBrowserFlow(
                request,
                "github",
                CONTEXT)).isEmpty();
    }

    @Test
    void secondaryBrowserProofRetainsPrimaryActorAndIntent() {
        UUID intentId = UUID.randomUUID();
        manager.recordPrimaryReauthentication(
                session,
                "usr_primary",
                "local-password");
        manager.startIntent(session, intentId, CONTEXT);
        manager.prepareSecondaryBrowserFlow(
                session,
                intentId,
                "cas-main",
                CONTEXT);
        manager.activateBrowserFlow(
                session,
                "cas-main",
                "cas-state");

        AccountMergeBrowserFlow.Secondary flow =
                (AccountMergeBrowserFlow.Secondary)
                        manager.consumeBrowserFlow(
                                        callbackRequest("cas-state"),
                                        "cas-main",
                                        CONTEXT)
                                .orElseThrow();

        assertThat(flow.intentId()).isEqualTo(intentId);
        assertThat(flow.actor().userId())
                .isEqualTo("usr_primary");
        assertThat(flow.providerCode())
                .isEqualTo("cas-main");
    }

    @Test
    void browserStateMismatchFailsClosedAndCannotBeRetried() {
        manager.preparePrimaryBrowserFlow(session, "github");
        manager.activateBrowserFlow(
                session,
                "github",
                "expected-state");
        MockHttpServletRequest request =
                callbackRequest("different-state");

        assertThatThrownBy(() ->
                manager.consumeBrowserFlow(
                        request,
                        "github",
                        CONTEXT))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_SESSION_MISMATCH));
        assertThat(manager.consumeBrowserFlow(
                request,
                "github",
                CONTEXT)).isEmpty();
    }

    private MockHttpServletRequest callbackRequest(
            String state) {
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        request.setSession(session);
        request.setParameter("state", state);
        return request;
    }
}
