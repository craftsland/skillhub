package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.cas.CasAuthenticationExchange;
import com.iflytek.skillhub.auth.cas.CasBrowserClient;
import com.iflytek.skillhub.auth.cas.CasLoginInitiation;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.provider.BrowserAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.session.PlatformSessionService;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

class CasLoginAppServiceTest {

    private static final String PROVIDER = "cas-main";
    private static final String STATE =
            "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-";
    private static final String SERVICE =
            "https://skill.example/api/v1/auth/cas/cas-main/callback"
                    + "?state="
                    + STATE;

    @Test
    void completesVerifiedExchangeThroughCoreBeforeEstablishingSession() {
        Fixture fixture = new Fixture();
        MockHttpServletRequest request = request();
        CasAuthenticationExchange exchange =
                new CasAuthenticationExchange(
                        "user-1",
                        Map.of(),
                        Instant.parse("2026-07-31T00:00:00Z"));
        ProviderAuthenticationResult result = result();
        PlatformPrincipal principal = principal();
        when(fixture.stateStore.consume(
                request.getSession().getId(),
                STATE)).thenReturn(Optional.of(loginState()));
        when(fixture.protocolClient.validate(
                PROVIDER,
                "ST-1",
                SERVICE)).thenReturn(exchange);
        when(fixture.route.adapter()).thenReturn(fixture.adapter);
        when(fixture.adapter.authenticate(exchange))
                .thenReturn(result);
        when(fixture.providerLogin.authenticate(
                isNull(),
                org.mockito.ArgumentMatchers.eq(result),
                org.mockito.ArgumentMatchers.eq(request)))
                .thenReturn(principal);

        assertThat(fixture.service.complete(
                PROVIDER,
                "ST-1",
                STATE,
                request)).isEqualTo("/skills");

        InOrder order = inOrder(
                fixture.stateStore,
                fixture.registry,
                fixture.protocolClient,
                fixture.adapter,
                fixture.providerLogin,
                fixture.sessions);
        order.verify(fixture.stateStore).consume(
                request.getSession().getId(),
                STATE);
        order.verify(fixture.registry).requireBrowserRoute(
                PROVIDER,
                CasAuthenticationExchange.class);
        order.verify(fixture.protocolClient).validate(
                PROVIDER,
                "ST-1",
                SERVICE);
        order.verify(fixture.adapter).authenticate(exchange);
        order.verify(fixture.providerLogin).authenticate(
                isNull(),
                org.mockito.ArgumentMatchers.eq(result),
                org.mockito.ArgumentMatchers.eq(request));
        order.verify(fixture.sessions)
                .establishSession(principal, request);
    }

    @Test
    void beginsWithReadyRouteAndPersistsStateBeforeRedirect() {
        Fixture fixture = new Fixture();
        MockHttpServletRequest request = request();
        URI loginUri = URI.create(
                "https://cas.example/login?service=fixture");
        when(fixture.protocolClient.begin(PROVIDER, STATE))
                .thenReturn(new CasLoginInitiation(
                        loginUri,
                        SERVICE,
                        Duration.ofMinutes(5)));

        assertThat(fixture.service.begin(
                PROVIDER,
                "/dashboard",
                request)).isEqualTo(loginUri);

        InOrder order = inOrder(
                fixture.registry,
                fixture.protocolClient,
                fixture.stateStore);
        order.verify(fixture.registry).requireBrowserRoute(
                PROVIDER,
                CasAuthenticationExchange.class);
        order.verify(fixture.protocolClient).begin(
                PROVIDER,
                STATE);
        order.verify(fixture.stateStore).save(
                request.getSession().getId(),
                STATE,
                PROVIDER,
                SERVICE,
                "/dashboard",
                Duration.ofMinutes(5));
    }

    @Test
    void missingOrReplayedStateNeverReachesCasServer() {
        Fixture fixture = new Fixture();
        MockHttpServletRequest request = request();
        when(fixture.stateStore.consume(
                request.getSession().getId(),
                STATE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> fixture.service.complete(
                PROVIDER,
                "ST-1",
                STATE,
                request))
                .isInstanceOf(CasLoginFlowException.class)
                .extracting("failure")
                .isEqualTo(CasLoginFailure.INVALID_STATE);
        verifyNoInteractions(
                fixture.protocolClient,
                fixture.adapter,
                fixture.providerLogin,
                fixture.sessions);
    }

    @Test
    void missingTicketConsumesStateButNeverCallsProvider() {
        Fixture fixture = new Fixture();
        MockHttpServletRequest request = request();
        when(fixture.stateStore.consume(
                request.getSession().getId(),
                STATE)).thenReturn(Optional.of(loginState()));

        assertThatThrownBy(() -> fixture.service.complete(
                PROVIDER,
                null,
                STATE,
                request))
                .isInstanceOf(CasLoginFlowException.class)
                .extracting("failure")
                .isEqualTo(CasLoginFailure.TICKET_MISSING);
        verify(fixture.stateStore).consume(
                request.getSession().getId(),
                STATE);
        verify(fixture.registry, never()).requireBrowserRoute(
                any(),
                any());
        verifyNoInteractions(
                fixture.protocolClient,
                fixture.adapter,
                fixture.providerLogin,
                fixture.sessions);
    }

    @Test
    void mapsStableUpstreamFailureWithoutCreatingSession() {
        Fixture fixture = new Fixture();
        MockHttpServletRequest request = request();
        when(fixture.stateStore.consume(
                request.getSession().getId(),
                STATE)).thenReturn(Optional.of(loginState()));
        when(fixture.protocolClient.validate(
                PROVIDER,
                "ST-1",
                SERVICE)).thenThrow(
                        new ProviderAuthenticationException(
                                ProviderAuthenticationFailureCode
                                        .TLS_VALIDATION_FAILED));

        assertThatThrownBy(() -> fixture.service.complete(
                PROVIDER,
                "ST-1",
                STATE,
                request))
                .isInstanceOf(CasLoginFlowException.class)
                .extracting("failure")
                .isEqualTo(CasLoginFailure.PROVIDER_UNAVAILABLE);
        verifyNoInteractions(
                fixture.adapter,
                fixture.providerLogin,
                fixture.sessions);
    }

    private static CasLoginStateStore.CasLoginState loginState() {
        return new CasLoginStateStore.CasLoginState(
                PROVIDER,
                SERVICE,
                "/skills",
                Instant.parse("2026-07-31T00:05:00Z"));
    }

    private static ProviderAuthenticationResult result() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "cas_principal",
                        "user-1"),
                List.of(),
                Map.of(),
                new ProtocolAuthenticationEvidence(
                        "cas",
                        Instant.parse("2026-07-31T00:00:00Z"),
                        Set.of("cas_service_ticket")));
    }

    private static PlatformPrincipal principal() {
        return new PlatformPrincipal(
                "usr_cas",
                "CAS User",
                null,
                null,
                PROVIDER,
                Set.of("USER"));
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        request.setSession(new MockHttpSession());
        return request;
    }

    private static final class Fixture {

        private final IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        private final CasBrowserClient protocolClient =
                mock(CasBrowserClient.class);
        private final ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        private final PlatformSessionService sessions =
                mock(PlatformSessionService.class);
        private final CasLoginStateStore stateStore =
                mock(CasLoginStateStore.class);
        @SuppressWarnings("unchecked")
        private final IdentityProviderRegistry.BrowserRoute
                <CasAuthenticationExchange> route =
                mock(IdentityProviderRegistry.BrowserRoute.class);
        @SuppressWarnings("unchecked")
        private final BrowserAuthenticationAdapter
                <CasAuthenticationExchange> adapter =
                mock(BrowserAuthenticationAdapter.class);
        private final CasLoginAppService service =
                new CasLoginAppService(
                        registry,
                        protocolClient,
                        providerLogin,
                        sessions,
                        stateStore,
                        () -> STATE);

        private Fixture() {
            when(registry.requireBrowserRoute(
                    PROVIDER,
                    CasAuthenticationExchange.class))
                    .thenReturn(route);
        }
    }
}
