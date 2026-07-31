package com.iflytek.skillhub.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "skillhub.auth.account-merge.enabled=true",
        "skillhub.auth.account-merge."
                + "session-cutover-complete=true"
})
class AccountMergeControllerEnabledTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private NamespaceMemberRepository namespaceMemberRepository;

    @MockBean
    @SuppressWarnings("rawtypes")
    private FindByIndexNameSessionRepository sessionRepository;

    @Autowired
    private UserAccountRepository userAccountRepository;

    @BeforeEach
    void seedPrimaryAccount() {
        if (userAccountRepository.findById("usr_primary")
                .isEmpty()) {
            userAccountRepository.save(new UserAccount(
                    "usr_primary",
                    "Primary",
                    "primary@example.com",
                    null));
        }
    }

    @Test
    void capabilitiesExposeTheEnabledResourceApi() throws Exception {
        mockMvc.perform(
                get("/api/v1/account/merge/capabilities")
                        .session(primarySession())
                        .with(authentication(
                                primaryAuthentication())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.enabled").value(true))
                .andExpect(jsonPath("$.data.primaryMethods")
                        .isArray())
                .andExpect(jsonPath("$.data.secondaryMethods")
                        .isArray());
    }

    @Test
    void resourceMutationStillRequiresCsrf() throws Exception {
        mockMvc.perform(
                post("/api/v1/account/merge/intents")
                        .session(primarySession())
                        .with(authentication(
                                primaryAuthentication())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void intentCreationRequiresAConsumedFreshPrimaryProof()
            throws Exception {
        mockMvc.perform(
                post("/api/v1/account/merge/intents")
                        .session(primarySession())
                        .with(authentication(
                                primaryAuthentication()))
                        .with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reasonCode").value(
                        "MERGE_REAUTH_REQUIRED"));
    }

    @Test
    void enablingTheNewFlowDoesNotReviveLegacyTokenEndpoints()
            throws Exception {
        mockMvc.perform(
                post("/api/v1/account/merge/initiate")
                        .session(primarySession())
                        .with(authentication(
                                primaryAuthentication()))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "secondaryIdentifier": "secondary"
                                }
                                """))
                .andExpect(status().isServiceUnavailable());
    }

    private UsernamePasswordAuthenticationToken
            primaryAuthentication() {
        return new UsernamePasswordAuthenticationToken(
                principal(),
                null,
                List.of());
    }

    private MockHttpSession primarySession() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                "platformPrincipal",
                principal());
        return session;
    }

    private PlatformPrincipal principal() {
        return new PlatformPrincipal(
                "usr_primary",
                "Primary",
                "primary@example.com",
                null,
                "local",
                Set.of());
    }
}
