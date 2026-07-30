package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

class CustomOAuth2UserServiceTest {

    @Test
    void passesCurrentHttpAuditContextIntoUnifiedLoginFlow() {
        OAuthLoginFlowService loginFlowService =
                mock(OAuthLoginFlowService.class);
        OAuthIdentityLoginContextResolver contextResolver =
                mock(OAuthIdentityLoginContextResolver.class);
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        IdentityLoginContext loginContext = new IdentityLoginContext(
                "req-123",
                "203.0.113.9",
                "SkillHub Browser");
        PlatformPrincipal principal = new PlatformPrincipal(
                "usr_1",
                "Alice",
                "alice@example.com",
                null,
                "github",
                Set.of("USER"));
        OAuth2User upstream = new DefaultOAuth2User(
                Set.of(new SimpleGrantedAuthority("OAUTH2_USER")),
                Map.of("id", "123"),
                "id");
        when(contextResolver.current()).thenReturn(loginContext);
        when(loginFlowService.loadLoginContext(request, loginContext))
                .thenReturn(new OAuthLoginFlowService.AuthenticatedLoginContext(
                        upstream,
                        principal));
        CustomOAuth2UserService service = new CustomOAuth2UserService(
                loginFlowService,
                contextResolver);

        OAuth2User loaded = service.loadUser(request);

        verify(loginFlowService).loadLoginContext(
                request,
                loginContext);
        assertThat((Object) loaded.getAttribute("platformPrincipal"))
                .isEqualTo(principal);
    }
}
