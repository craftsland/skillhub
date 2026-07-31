package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

/**
 * OAuth2 authorization request resolver that preserves a sanitized post-login redirect target in
 * the HTTP session.
 */
@Component
public class SkillHubOAuth2AuthorizationRequestResolver
        implements org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver delegate;
    private final OAuthLoginFlowService oauthLoginFlowService;
    private final IdentityLinkSessionManager identityLinkSessionManager;
    private final AccountMergeSessionManager
            accountMergeSessionManager;

    public SkillHubOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                                      OAuthLoginFlowService oauthLoginFlowService,
                                                      IdentityLinkSessionManager identityLinkSessionManager,
                                                      AccountMergeSessionManager
                                                              accountMergeSessionManager) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                "/oauth2/authorization"
        );
        this.oauthLoginFlowService = oauthLoginFlowService;
        this.identityLinkSessionManager = identityLinkSessionManager;
        this.accountMergeSessionManager =
                accountMergeSessionManager;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest = delegate.resolve(request);
        rememberAuthorizationFlow(request, authorizationRequest);
        return authorizationRequest;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest = delegate.resolve(request, clientRegistrationId);
        rememberAuthorizationFlow(request, authorizationRequest);
        return authorizationRequest;
    }

    private void rememberAuthorizationFlow(
            HttpServletRequest request,
            OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            return;
        }
        oauthLoginFlowService.rememberReturnTo(request);
        String registrationId = authorizationRequest.getAttribute(
                "registration_id");
        identityLinkSessionManager.activateBrowserFlow(
                request.getSession(false),
                registrationId,
                authorizationRequest.getState());
        accountMergeSessionManager.activateBrowserFlow(
                request.getSession(false),
                registrationId,
                authorizationRequest.getState());
    }
}
