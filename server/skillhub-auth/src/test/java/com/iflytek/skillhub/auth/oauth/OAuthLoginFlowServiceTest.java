package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.IdentityBindingService;
import com.iflytek.skillhub.auth.policy.AccessDecision;
import com.iflytek.skillhub.auth.policy.AccessPolicy;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.user.UserStatus;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuthLoginFlowServiceTest {

    @Test
    void authenticate_allowsPreviouslyApprovedUserWhenPolicyRequiresApproval() {
        AccessPolicy accessPolicy = mock(AccessPolicy.class);
        IdentityBindingService identityBindingService = mock(IdentityBindingService.class);
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(),
                accessPolicy,
                identityBindingService
        );
        OAuthClaims claims = claims();
        PlatformPrincipal approvedPrincipal = new PlatformPrincipal(
                "usr_1", "alice", "alice@example.com", null, "github", Set.of("USER"));
        when(accessPolicy.evaluate(claims)).thenReturn(AccessDecision.PENDING_APPROVAL);
        when(identityBindingService.bindOrCreate(claims, UserStatus.PENDING)).thenReturn(approvedPrincipal);

        PlatformPrincipal principal = service.authenticate(claims);

        assertThat(principal).isSameAs(approvedPrincipal);
        verify(identityBindingService).bindOrCreate(claims, UserStatus.PENDING);
    }

    @Test
    void authenticate_rejectsDisabledUserWhenPolicyRequiresApproval() {
        AccessPolicy accessPolicy = mock(AccessPolicy.class);
        IdentityBindingService identityBindingService = mock(IdentityBindingService.class);
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(),
                accessPolicy,
                identityBindingService
        );
        OAuthClaims claims = claims();
        when(accessPolicy.evaluate(claims)).thenReturn(AccessDecision.PENDING_APPROVAL);
        when(identityBindingService.bindOrCreate(claims, UserStatus.PENDING))
                .thenThrow(new AccountDisabledException());

        assertThatThrownBy(() -> service.authenticate(claims))
                .isInstanceOf(AccountDisabledException.class);
    }

    @Test
    void rememberReturnTo_stores_sanitized_return_target() {
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(),
                mock(AccessPolicy.class),
                mock(IdentityBindingService.class)
        );
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("returnTo", "/dashboard/publish");

        service.rememberReturnTo(request);

        HttpSession session = request.getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE))
                .isEqualTo("/dashboard/publish");
    }

    @Test
    void resolveFailureRedirect_maps_access_denied_to_user_facing_page() {
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(),
                mock(AccessPolicy.class),
                mock(IdentityBindingService.class)
        );

        String redirect = service.resolveFailureRedirect(
                new OAuth2AuthenticationException(new OAuth2Error("access_denied")),
                "/settings/accounts"
        );

        assertThat(redirect).isEqualTo("/access-denied");
    }

    @Test
    void resolveFailureRedirect_mapsMergedAccountToAccessDenied() {
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(),
                mock(AccessPolicy.class),
                mock(IdentityBindingService.class)
        );

        assertThat(service.resolveFailureRedirect(new AccountMergedException(), null))
                .isEqualTo("/access-denied");
    }

    @Test
    void resolveFailureRedirect_mapsSystemAccountToAccessDenied() {
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(),
                mock(AccessPolicy.class),
                mock(IdentityBindingService.class)
        );

        assertThat(service.resolveFailureRedirect(new SystemAccountLoginException(), null))
                .isEqualTo("/access-denied");
    }

    @Test
    void consumeReturnTo_clearsUnsafeSessionValue() {
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(),
                mock(AccessPolicy.class),
                mock(IdentityBindingService.class)
        );
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);
        session.setAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE, "https://evil.example");

        String returnTo = service.consumeReturnTo(session);

        assertThat(returnTo).isNull();
        assertThat(session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE)).isNull();
    }

    private OAuthClaims claims() {
        return new OAuthClaims(
                "github",
                "gh_1",
                "alice@example.com",
                true,
                "alice",
                Map.of()
        );
    }
}
