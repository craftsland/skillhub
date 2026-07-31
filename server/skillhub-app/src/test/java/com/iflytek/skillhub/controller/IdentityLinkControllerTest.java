package com.iflytek.skillhub.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.iflytek.skillhub.auth.entity.IdentityLinkOperation;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import com.iflytek.skillhub.auth.identity.IdentityLinkException;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.iflytek.skillhub.dto.IdentityLinkIntentResponse;
import com.iflytek.skillhub.service.IdentityLinkAppService;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdentityLinkControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IdentityLinkAppService appService;

    @MockBean
    private NamespaceMemberRepository namespaceMemberRepository;

    @Test
    void createLinkIntentRequiresAuthenticatedSessionAndCsrf()
            throws Exception {
        UUID intentId = UUID.randomUUID();
        given(appService.createLinkIntent(
                eq("github"),
                any(),
                any()))
                .willReturn(new IdentityLinkIntentResponse(
                        intentId,
                        IdentityLinkOperation.LINK,
                        IdentityLinkRequestStatus
                                .PENDING_REAUTHENTICATION,
                        "github",
                        null,
                        Instant.parse(
                                "2026-07-31T08:10:00Z")));

        mockMvc.perform(
                post("/api/v1/auth/identity-link-intents/link")
                        .with(authentication(currentAuthentication()))
                        .with(csrf())
                        .session(session())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"providerCode":"github"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data.id")
                        .value(intentId.toString()))
                .andExpect(jsonPath("$.data.status")
                        .value("PENDING_REAUTHENTICATION"));
        verify(appService).createLinkIntent(
                eq("github"),
                any(),
                any());
    }

    @Test
    void createLinkIntentWithoutCsrfIsRejected() throws Exception {
        mockMvc.perform(
                post("/api/v1/auth/identity-link-intents/link")
                        .with(authentication(currentAuthentication()))
                        .session(session())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"providerCode":"github"}
                        """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reasonCode")
                        .value("REAUTHENTICATION_REQUIRED"));

        verify(appService, never()).createLinkIntent(
                any(),
                any(),
                any());
    }

    @Test
    void createLinkIntentWithoutAuthenticationIsRejected()
            throws Exception {
        mockMvc.perform(
                post("/api/v1/auth/identity-link-intents/link")
                        .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"providerCode":"github"}
                        """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reasonCode")
                        .value("REAUTHENTICATION_REQUIRED"));

        verify(appService, never()).createLinkIntent(
                any(),
                any(),
                any());
    }

    @Test
    void invalidProviderCodeIsRejectedBeforeAppService()
            throws Exception {
        mockMvc.perform(
                post("/api/v1/auth/identity-link-intents/link")
                        .with(authentication(currentAuthentication()))
                        .with(csrf())
                        .session(session())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"providerCode":"../../other"}
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reasonCode")
                        .value("INVALID_OPERATION"));

        verify(appService, never()).createLinkIntent(
                any(),
                any(),
                any());
    }

    @Test
    void missingBindingIdUsesIdentityLinkErrorContract()
            throws Exception {
        mockMvc.perform(
                post("/api/v1/auth/identity-link-intents/unlink")
                        .with(authentication(currentAuthentication()))
                        .with(csrf())
                        .session(session())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reasonCode")
                        .value("INVALID_OPERATION"));

        verify(appService, never()).createUnlinkIntent(
                anyLong(),
                any(),
                any());
    }

    @Test
    void localReauthenticationDoesNotCreateANewSession()
            throws Exception {
        UUID intentId = UUID.randomUUID();
        MockHttpSession session = session();
        String sessionId = session.getId();
        given(appService.reauthenticateLocal(
                eq(intentId),
                eq("IdentityLinkTest!2026"),
                any(),
                any()))
                .willReturn(new IdentityLinkIntentResponse(
                        intentId,
                        IdentityLinkOperation.UNLINK,
                        IdentityLinkRequestStatus.READY,
                        "github",
                        42L,
                        Instant.parse(
                                "2026-07-31T08:10:00Z")));

        mockMvc.perform(post(
                "/api/v1/auth/identity-link-intents/"
                        + intentId
                        + "/reauthenticate/local")
                .with(authentication(currentAuthentication()))
                .with(csrf())
                .session(session)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"password":"IdentityLinkTest!2026"}
                        """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status")
                        .value("READY"));

        org.assertj.core.api.Assertions.assertThat(
                session.getId()).isEqualTo(sessionId);
    }

    @Test
    void identityLinkFailureIncludesStableReasonCode()
            throws Exception {
        UUID intentId = UUID.randomUUID();
        given(appService.completeUnlink(
                eq(intentId),
                any(),
                any()))
                .willThrow(new IdentityLinkException(
                        IdentityLinkFailureCode
                                .FINAL_LOGIN_METHOD));

        mockMvc.perform(post(
                "/api/v1/auth/identity-link-intents/"
                        + intentId
                        + "/unlink")
                .with(authentication(currentAuthentication()))
                .with(csrf())
                .session(session()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(409))
                .andExpect(jsonPath("$.reasonCode")
                        .value("FINAL_LOGIN_METHOD"));
    }

    private MockHttpSession session() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                "platformPrincipal",
                principal());
        return session;
    }

    private UsernamePasswordAuthenticationToken currentAuthentication() {
        return new UsernamePasswordAuthenticationToken(
                principal(),
                null,
                List.of());
    }

    private PlatformPrincipal principal() {
        return new PlatformPrincipal(
                "usr_1",
                "Alice",
                "alice@example.com",
                null,
                "local",
                Set.of("USER"));
    }
}
