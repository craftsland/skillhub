package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.entity.IdentityLinkOperation;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import com.iflytek.skillhub.auth.identity.ExternalIdentityLinkService;
import com.iflytek.skillhub.auth.identity.IdentityLinkActor;
import com.iflytek.skillhub.auth.identity.IdentityLinkBrowserPhase;
import com.iflytek.skillhub.auth.identity.IdentityLinkException;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLinkIntent;
import com.iflytek.skillhub.auth.identity.IdentityLinkIntentService;
import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethod;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IdentityLinkAppServiceTest {

    private static final UUID INTENT_ID = UUID.fromString(
            "b731a62c-c168-4d58-8fcb-2f2461748d04");
    private static final String PROVIDER = "cas-main";

    @Test
    void preparesCasReauthenticationWithTheSharedBrowserIntent() {
        Fixture fixture = new Fixture();
        IdentityLinkIntent pending = intent(
                IdentityLinkRequestStatus.PENDING_REAUTHENTICATION);
        when(fixture.registry.listReadyLoginMethods())
                .thenReturn(List.of(casMethod()));
        when(fixture.intentService.prepareExternalReauthentication(
                fixture.actor,
                INTENT_ID,
                PROVIDER,
                IdentityProviderLoginMethodType.CAS_REDIRECT))
                .thenReturn(pending);

        String actionUrl =
                fixture.service.prepareBrowserReauthentication(
                INTENT_ID,
                PROVIDER,
                fixture.session,
                fixture.context);
        assertCasAction(
                actionUrl,
                "/settings/security?identityLink=reauthenticated"
                        + "&intentId="
                        + INTENT_ID);

        verify(fixture.sessionManager).prepareBrowserFlow(
                fixture.session,
                INTENT_ID,
                IdentityLinkBrowserPhase.REAUTHENTICATE,
                PROVIDER,
                fixture.context);
        verify(fixture.accountMergeSessionManager)
                .clearBrowserFlow(fixture.session);
    }

    @Test
    void preparesCasTargetAuthenticationAfterFreshReauthentication() {
        Fixture fixture = new Fixture();
        IdentityLinkIntent ready = intent(
                IdentityLinkRequestStatus.READY);
        when(fixture.registry.listReadyLoginMethods())
                .thenReturn(List.of(casMethod()));
        when(fixture.intentService.getIntent(
                fixture.actor,
                INTENT_ID)).thenReturn(ready);
        when(fixture.intentService.prepareExternalLink(
                fixture.actor,
                INTENT_ID,
                IdentityProviderLoginMethodType.CAS_REDIRECT))
                .thenReturn(ready);

        String actionUrl = fixture.service.prepareBrowserLink(
                INTENT_ID,
                fixture.session,
                fixture.context);
        assertCasAction(
                actionUrl,
                "/settings/security?identityLink=linked"
                        + "&intentId="
                        + INTENT_ID);

        verify(fixture.sessionManager).prepareBrowserFlow(
                fixture.session,
                INTENT_ID,
                IdentityLinkBrowserPhase.LINK,
                PROVIDER,
                fixture.context);
        verify(fixture.accountMergeSessionManager)
                .clearBrowserFlow(fixture.session);
    }

    @Test
    void browserEndpointRejectsCredentialOnlyProvider() {
        Fixture fixture = new Fixture();
        when(fixture.registry.listReadyLoginMethods())
                .thenReturn(List.of(new IdentityProviderLoginMethod(
                        PROVIDER,
                        "Corporate Directory",
                        IdentityProviderLoginMethodType
                                .DIRECT_PASSWORD)));

        assertThatThrownBy(() ->
                fixture.service.prepareBrowserReauthentication(
                        INTENT_ID,
                        PROVIDER,
                        fixture.session,
                        fixture.context))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .PROVIDER_UNAVAILABLE));
    }

    private static IdentityProviderLoginMethod casMethod() {
        return new IdentityProviderLoginMethod(
                PROVIDER,
                "Corporate CAS",
                IdentityProviderLoginMethodType.CAS_REDIRECT);
    }

    private static void assertCasAction(
            String actionUrl,
            String expectedReturnTo) {
        URI uri = URI.create(actionUrl);
        assertThat(uri.getPath()).isEqualTo(
                "/api/v1/auth/cas/cas-main/login");
        assertThat(uri.getRawQuery()).startsWith("returnTo=");
        assertThat(URLDecoder.decode(
                uri.getRawQuery().substring("returnTo=".length()),
                StandardCharsets.UTF_8))
                .isEqualTo(expectedReturnTo);
    }

    private static IdentityLinkIntent intent(
            IdentityLinkRequestStatus status) {
        return new IdentityLinkIntent(
                INTENT_ID,
                IdentityLinkOperation.LINK,
                status,
                PROVIDER,
                null,
                Instant.parse("2026-07-31T08:10:00Z"));
    }

    private static final class Fixture {

        private final IdentityLinkIntentService intentService =
                mock(IdentityLinkIntentService.class);
        private final ExternalIdentityLinkService externalLinkService =
                mock(ExternalIdentityLinkService.class);
        private final IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        private final IdentityLinkSessionManager sessionManager =
                mock(IdentityLinkSessionManager.class);
        private final AccountMergeSessionManager
                accountMergeSessionManager =
                mock(AccountMergeSessionManager.class);
        private final HttpSession session = mock(HttpSession.class);
        private final IdentityLoginContext context =
                new IdentityLoginContext(
                        "req-1",
                        "127.0.0.1",
                        "JUnit");
        private final IdentityLinkActor actor =
                new IdentityLinkActor(
                        "usr_1",
                        "local",
                        "session-nonce",
                        context);
        private final IdentityLinkAppService service =
                new IdentityLinkAppService(
                        intentService,
                        externalLinkService,
                        registry,
                        sessionManager,
                        accountMergeSessionManager);

        private Fixture() {
            when(sessionManager.actor(
                    session,
                    INTENT_ID,
                    context)).thenReturn(actor);
        }
    }
}
