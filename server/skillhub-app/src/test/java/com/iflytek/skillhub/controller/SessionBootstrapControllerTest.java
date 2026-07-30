package com.iflytek.skillhub.controller;

import com.iflytek.skillhub.auth.local.LocalCredentialRepository;
import com.iflytek.skillhub.auth.repository.UserRoleBindingRepository;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.exception.BadRequestException;
import com.iflytek.skillhub.service.SessionBootstrapService;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.BDDMockito.given;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "skillhub.auth.session-bootstrap.enabled=true"
})
class SessionBootstrapControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private NamespaceMemberRepository namespaceMemberRepository;

    @MockBean
    private UserAccountRepository userAccountRepository;

    @MockBean
    private UserRoleBindingRepository userRoleBindingRepository;

    @MockBean
    private LocalCredentialRepository localCredentialRepository;

    @MockBean
    private SessionBootstrapService sessionBootstrapService;

    @Test
    void sessionBootstrapShouldEstablishSessionWhenAuthenticatorSucceeds() throws Exception {
        PlatformPrincipal principal = new PlatformPrincipal(
            "sso-user-1",
            "Private SSO User",
            null,
            null,
            "private-sso",
            Set.of("USER")
        );
        given(sessionBootstrapService.bootstrap(
            org.mockito.ArgumentMatchers.eq("private-sso"),
            any()
        )).willReturn(principal);
        given(namespaceMemberRepository.findByUserId("sso-user-1")).willReturn(List.of());
        given(userAccountRepository.findById("sso-user-1"))
            .willReturn(Optional.of(new UserAccount("sso-user-1", "Private SSO User", null, null)));
        given(userRoleBindingRepository.findByUserId("sso-user-1")).willReturn(List.of());
        given(localCredentialRepository.existsByUserId("sso-user-1")).willReturn(false);

        mockMvc.perform(post("/api/v1/auth/session/bootstrap")
                .with(csrf())
                .contentType("application/json")
                .content("""
                    {"provider":"private-sso"}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.code").value(0))
            .andExpect(jsonPath("$.data.userId").value("sso-user-1"))
            .andExpect(jsonPath("$.data.displayName").value("Private SSO User"))
            .andExpect(jsonPath("$.data.canChangePassword").value(false));
    }

    @Test
    void sessionBootstrapShouldRejectUnsupportedProvider() throws Exception {
        given(sessionBootstrapService.bootstrap(
            org.mockito.ArgumentMatchers.eq("unknown"),
            any()
        )).willThrow(new BadRequestException(
            "error.auth.sessionBootstrap.providerUnsupported",
            "unknown"
        ));

        mockMvc.perform(post("/api/v1/auth/session/bootstrap")
                .with(csrf())
                .contentType("application/json")
                .content("""
                    {"provider":"unknown"}
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value(400));
    }
}
