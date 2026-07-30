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
import com.iflytek.skillhub.auth.local.LocalAuthService;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.config.DirectAuthProperties;
import com.iflytek.skillhub.exception.BadRequestException;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class DirectAuthServiceTest {

    @Test
    void resolvesReadyRouteBeforeSendingCredentialsToAdapter() {
        DirectAuthProperties properties = new DirectAuthProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        LocalAuthService localAuth = mock(LocalAuthService.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        SessionBootstrapService sessions =
                mock(SessionBootstrapService.class);
        CredentialAuthenticationAdapter adapter =
                mock(CredentialAuthenticationAdapter.class);
        IdentityProviderRegistry.CredentialRoute route =
                mock(IdentityProviderRegistry.CredentialRoute.class);
        ProviderAuthenticationResult result = result();
        PlatformPrincipal principal = new PlatformPrincipal(
                "usr_directory",
                "Directory User",
                null,
                null,
                "directory",
                Set.of("USER"));
        HttpServletRequest request =
                mock(HttpServletRequest.class);

        when(registry.requireCredentialRoute("directory"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(any()))
                .thenReturn(result);
        when(providerLogin.authenticate(
                isNull(),
                org.mockito.ArgumentMatchers.eq(result),
                org.mockito.ArgumentMatchers.eq(request)))
                .thenReturn(principal);
        DirectAuthService service = new DirectAuthService(
                properties,
                registry,
                localAuth,
                providerLogin,
                sessions);

        assertThat(service.authenticate(
                "directory",
                "alice",
                "secret",
                request)).isSameAs(principal);
        ArgumentCaptor<CredentialAuthenticationRequest> credentials =
                ArgumentCaptor.forClass(
                        CredentialAuthenticationRequest.class);
        InOrder order = inOrder(
                registry,
                adapter,
                providerLogin,
                sessions);
        order.verify(registry)
                .requireCredentialRoute("directory");
        order.verify(adapter)
                .authenticate(credentials.capture());
        order.verify(providerLogin).authenticate(
                isNull(),
                org.mockito.ArgumentMatchers.eq(result),
                org.mockito.ArgumentMatchers.eq(request));
        order.verify(sessions)
                .establishSession(principal, request);
        assertThat(credentials.getValue())
                .isEqualTo(new CredentialAuthenticationRequest(
                        "alice",
                        "secret"));
        verifyNoInteractions(localAuth);
    }

    @Test
    void unavailableProviderCannotReceiveCredentials() {
        DirectAuthProperties properties = new DirectAuthProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        LocalAuthService localAuth = mock(LocalAuthService.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        SessionBootstrapService sessions =
                mock(SessionBootstrapService.class);
        CredentialAuthenticationAdapter adapter =
                mock(CredentialAuthenticationAdapter.class);
        HttpServletRequest request =
                mock(HttpServletRequest.class);
        when(registry.requireCredentialRoute("disabled"))
                .thenThrow(new IdentityCoreException(
                        IdentityFailureCode.PROVIDER_DISABLED));
        DirectAuthService service = new DirectAuthService(
                properties,
                registry,
                localAuth,
                providerLogin,
                sessions);

        assertThatThrownBy(() -> service.authenticate(
                "disabled",
                "alice",
                "secret",
                request)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(
                adapter,
                localAuth,
                providerLogin,
                sessions);
    }

    @Test
    void nullAdapterResultIsRejectedBeforeCoreOrSession() {
        DirectAuthProperties properties = new DirectAuthProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        LocalAuthService localAuth = mock(LocalAuthService.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        SessionBootstrapService sessions =
                mock(SessionBootstrapService.class);
        CredentialAuthenticationAdapter adapter =
                mock(CredentialAuthenticationAdapter.class);
        IdentityProviderRegistry.CredentialRoute route =
                mock(IdentityProviderRegistry.CredentialRoute.class);
        HttpServletRequest request =
                mock(HttpServletRequest.class);
        when(registry.requireCredentialRoute("broken"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(any())).thenReturn(null);
        DirectAuthService service = new DirectAuthService(
                properties,
                registry,
                localAuth,
                providerLogin,
                sessions);

        assertThatThrownBy(() -> service.authenticate(
                "broken",
                "alice",
                "secret",
                request)).isInstanceOf(AuthFlowException.class)
                .extracting("status")
                .isEqualTo(org.springframework.http.HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(
                localAuth,
                providerLogin,
                sessions);
    }

    @Test
    void stableAdapterFailureIsMappedBeforeCoreOrSession() {
        DirectAuthProperties properties = new DirectAuthProperties();
        properties.setEnabled(true);
        IdentityProviderRegistry registry =
                mock(IdentityProviderRegistry.class);
        LocalAuthService localAuth = mock(LocalAuthService.class);
        ProviderLoginAppService providerLogin =
                mock(ProviderLoginAppService.class);
        SessionBootstrapService sessions =
                mock(SessionBootstrapService.class);
        CredentialAuthenticationAdapter adapter =
                mock(CredentialAuthenticationAdapter.class);
        IdentityProviderRegistry.CredentialRoute route =
                mock(IdentityProviderRegistry.CredentialRoute.class);
        HttpServletRequest request =
                mock(HttpServletRequest.class);
        when(registry.requireCredentialRoute("directory"))
                .thenReturn(route);
        when(route.adapter()).thenReturn(adapter);
        when(adapter.authenticate(any())).thenThrow(
                new ProviderAuthenticationException(
                        ProviderAuthenticationFailureCode
                                .UPSTREAM_UNAVAILABLE));
        DirectAuthService service = new DirectAuthService(
                properties,
                registry,
                localAuth,
                providerLogin,
                sessions);

        assertThatThrownBy(() -> service.authenticate(
                "directory",
                "alice",
                "secret",
                request)).isInstanceOf(AuthFlowException.class)
                .extracting("status")
                .isEqualTo(
                        org.springframework.http.HttpStatus
                                .SERVICE_UNAVAILABLE);
        verifyNoInteractions(localAuth, providerLogin, sessions);
    }

    private static ProviderAuthenticationResult result() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "directory_subject",
                        "subject-1"),
                List.of(),
                Map.of(),
                new ProtocolAuthenticationEvidence(
                        "ldap",
                        Instant.parse("2026-07-30T00:00:00Z"),
                        Set.of("password")));
    }
}
