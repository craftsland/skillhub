package com.iflytek.skillhub.controller.admin;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.iflytek.skillhub.auth.device.DeviceAuthService;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.iflytek.skillhub.dto.IdentityProviderAuthorityRecoveryResponse;
import com.iflytek.skillhub.service.IdentityProviderAdminAppService;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdentityProviderAdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IdentityProviderAdminAppService providerAdminAppService;

    @MockBean
    private NamespaceMemberRepository namespaceMemberRepository;

    @MockBean
    private DeviceAuthService deviceAuthService;

    @Test
    void superAdminCanRecoverSameAuthority() throws Exception {
        when(providerAdminAppService.recoverSameAuthority(
                eq("github"),
                eq("admin"),
                any())).thenReturn(
                        new IdentityProviderAuthorityRecoveryResponse(
                                "github",
                                true,
                                "READY"));

        mockMvc.perform(post(
                        "/api/v1/admin/identity-providers/github/authority/recover")
                        .with(authentication(superAdminAuth()))
                        .with(csrf())
                        .header("User-Agent", "SkillHub Browser"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data.providerCode")
                        .value("github"))
                .andExpect(jsonPath("$.data.recovered").value(true))
                .andExpect(jsonPath("$.data.state").value("READY"));

        verify(providerAdminAppService).recoverSameAuthority(
                eq("github"),
                eq("admin"),
                any());
    }

    @Test
    void nonSuperAdminCannotRecoverProviderAuthority()
            throws Exception {
        mockMvc.perform(post(
                        "/api/v1/admin/identity-providers/github/authority/recover")
                        .with(authentication(userAdminAuth()))
                        .with(csrf()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(403));
    }

    private static UsernamePasswordAuthenticationToken
            superAdminAuth() {
        return principalAuthentication(
                "admin",
                "SUPER_ADMIN");
    }

    private static UsernamePasswordAuthenticationToken
            userAdminAuth() {
        return principalAuthentication(
                "user-admin",
                "USER_ADMIN");
    }

    private static UsernamePasswordAuthenticationToken principalAuthentication(
            String userId,
            String role) {
        PlatformPrincipal principal = new PlatformPrincipal(
                userId,
                userId,
                userId + "@example.com",
                null,
                "local",
                Set.of(role));
        return new UsernamePasswordAuthenticationToken(
                principal,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_" + role)));
    }
}
