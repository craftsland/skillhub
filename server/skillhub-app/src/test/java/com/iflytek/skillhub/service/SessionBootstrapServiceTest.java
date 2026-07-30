package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
import org.mockito.InOrder;

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
        HttpServletRequest request =
                mock(HttpServletRequest.class);

        when(registry.requirePassiveRoute("private-sso"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(request))
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
        order.verify(adapter).authenticate(request);
        order.verify(providerLogin).authenticate(
                isNull(),
                org.mockito.ArgumentMatchers.eq(result),
                org.mockito.ArgumentMatchers.eq(request));
        order.verify(sessions)
                .establishSession(principal, request);
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
        HttpServletRequest request =
                mock(HttpServletRequest.class);
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
        HttpServletRequest request =
                mock(HttpServletRequest.class);
        when(registry.requirePassiveRoute("broken"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(request)).thenReturn(null);
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
        HttpServletRequest request =
                mock(HttpServletRequest.class);
        when(registry.requirePassiveRoute("private-sso"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(request)).thenThrow(
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
}
