package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.provider.PassiveAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.PassiveAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.session.PlatformSessionService;
import com.iflytek.skillhub.config.AuthSessionBootstrapProperties;
import com.iflytek.skillhub.exception.BadRequestException;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.mock.web.MockHttpServletRequest;

class SessionBootstrapServiceTest {

    @Test
    void resolvesReadyRouteBeforeInvokingAdapterAndCore() {
        AuthSessionBootstrapProperties properties =
                new AuthSessionBootstrapProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        PlatformSessionService sessions =
                mock(PlatformSessionService.class);
        PassiveAuthenticationAdapter adapter =
                mock(PassiveAuthenticationAdapter.class);
        IdentityProviderRegistry.PassiveRoute route =
                mock(IdentityProviderRegistry.PassiveRoute.class);
        ProviderAuthenticationResult result = result();
        PlatformPrincipal principal = new PlatformPrincipal(
                "usr_private",
                "Private User",
                null,
                null,
                "private-sso",
                Set.of("USER"));
        HttpServletRequest request = request();

        when(registry.requirePassiveRoute("private-sso"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(any(PassiveAuthenticationRequest.class)))
                .thenReturn(Optional.of(result));
        when(providerLogin.authenticate(
                isNull(),
                org.mockito.ArgumentMatchers.eq(result),
                org.mockito.ArgumentMatchers.eq(request)))
                .thenReturn(principal);

        SessionBootstrapService service =
                new SessionBootstrapService(
                        properties,
                        registry,
                        providerLogin,
                        sessions);

        assertThat(service.bootstrap("private-sso", request))
                .isSameAs(principal);
        InOrder order = inOrder(
                registry,
                adapter,
                providerLogin,
                sessions);
        order.verify(registry)
                .requirePassiveRoute("private-sso");
        ArgumentCaptor<PassiveAuthenticationRequest> requestCaptor =
                ArgumentCaptor.forClass(
                        PassiveAuthenticationRequest.class);
        order.verify(adapter).authenticate(requestCaptor.capture());
        order.verify(providerLogin).authenticate(
                isNull(),
                org.mockito.ArgumentMatchers.eq(result),
                org.mockito.ArgumentMatchers.eq(request));
        order.verify(sessions)
                .establishSession(principal, request);
        PassiveAuthenticationRequest captured = requestCaptor.getValue();
        assertThat(captured.method()).isEqualTo("POST");
        assertThat(captured.requestUri())
                .isEqualTo("/api/v1/auth/session/bootstrap");
        assertThat(captured.remoteAddress()).isEqualTo("203.0.113.9");
        assertThat(captured.firstHeader("x-private-assertion"))
                .isEqualTo("fixture-assertion");
    }

    @Test
    void unavailableProviderCannotInvokeAdapter() {
        AuthSessionBootstrapProperties properties =
                new AuthSessionBootstrapProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        PlatformSessionService sessions =
                mock(PlatformSessionService.class);
        PassiveAuthenticationAdapter adapter =
                mock(PassiveAuthenticationAdapter.class);
        HttpServletRequest request = request();
        when(registry.requirePassiveRoute("disabled"))
                .thenThrow(new IdentityCoreException(
                        IdentityFailureCode.PROVIDER_DISABLED));
        SessionBootstrapService service =
                new SessionBootstrapService(
                        properties,
                        registry,
                        providerLogin,
                        sessions);

        assertThatThrownBy(
                () -> service.bootstrap("disabled", request))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(
                adapter,
                providerLogin,
                sessions);
    }

    @Test
    void nullOptionalFromAdapterIsRejectedBeforeCoreOrSession() {
        AuthSessionBootstrapProperties properties =
                new AuthSessionBootstrapProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        PlatformSessionService sessions =
                mock(PlatformSessionService.class);
        PassiveAuthenticationAdapter adapter =
                mock(PassiveAuthenticationAdapter.class);
        IdentityProviderRegistry.PassiveRoute route =
                mock(IdentityProviderRegistry.PassiveRoute.class);
        HttpServletRequest request = request();
        when(registry.requirePassiveRoute("broken"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(any(PassiveAuthenticationRequest.class)))
                .thenReturn(null);
        SessionBootstrapService service =
                new SessionBootstrapService(
                        properties,
                        registry,
                        providerLogin,
                        sessions);

        assertThatThrownBy(
                () -> service.bootstrap("broken", request))
                .isInstanceOf(AuthFlowException.class)
                .extracting("status")
                .isEqualTo(org.springframework.http.HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(providerLogin, sessions);
    }

    @Test
    void stableAdapterFailureIsMappedBeforeCoreOrSession() {
        AuthSessionBootstrapProperties properties =
                new AuthSessionBootstrapProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        PlatformSessionService sessions =
                mock(PlatformSessionService.class);
        PassiveAuthenticationAdapter adapter =
                mock(PassiveAuthenticationAdapter.class);
        IdentityProviderRegistry.PassiveRoute route =
                mock(IdentityProviderRegistry.PassiveRoute.class);
        HttpServletRequest request = request();
        when(registry.requirePassiveRoute("private-sso"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(any(PassiveAuthenticationRequest.class)))
                .thenThrow(
                        new ProviderAuthenticationException(
                                ProviderAuthenticationFailureCode
                                        .REPLAY_DETECTED));
        SessionBootstrapService service =
                new SessionBootstrapService(
                        properties,
                        registry,
                        providerLogin,
                        sessions);

        assertThatThrownBy(
                () -> service.bootstrap("private-sso", request))
                .isInstanceOf(AuthFlowException.class)
                .extracting("status")
                .isEqualTo(
                        org.springframework.http.HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(providerLogin, sessions);
    }

    private static ProviderAuthenticationResult result() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "private_subject",
                        "subject-1"),
                List.of(),
                Map.of(),
                new ProtocolAuthenticationEvidence(
                        "private-sso",
                        Instant.parse("2026-07-30T00:00:00Z"),
                        Set.of("sso")));
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "POST",
                "/api/v1/auth/session/bootstrap");
        request.setRemoteAddr("203.0.113.9");
        request.addHeader(
                "X-Private-Assertion",
                "fixture-assertion");
        return request;
    }
}
