package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.merge.AccountMergeBrowserFlowReference;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/**
 * Failure handler for OAuth logins that normalizes policy and account-state
 * failures into predictable user-facing redirects.
 */
@Component
public class OAuth2LoginFailureHandler
        extends SimpleUrlAuthenticationFailureHandler {

    private final OAuthLoginFlowService oauthLoginFlowService;
    private final IdentityLinkSessionManager identityLinkSessionManager;
    private final AccountMergeSessionManager
            accountMergeSessionManager;

    public OAuth2LoginFailureHandler(
            OAuthLoginFlowService oauthLoginFlowService,
            IdentityLinkSessionManager identityLinkSessionManager,
            AccountMergeSessionManager
                    accountMergeSessionManager) {
        this.oauthLoginFlowService = oauthLoginFlowService;
        this.identityLinkSessionManager = identityLinkSessionManager;
        this.accountMergeSessionManager =
                accountMergeSessionManager;
    }

    /**
     * Converts a pre-upstream route failure into an Identity Link callback
     * result only when this session actually owns a pending browser flow.
     * Normal OAuth login readiness failures retain their existing HTTP
     * status behavior.
     */
    public boolean redirectIdentityLinkRouteFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            IdentityLinkFailureCode reasonCode)
            throws IOException {
        return redirectSecurityFlowRouteFailure(
                request,
                response,
                AccountMergeFailureCode
                        .MERGE_PROVIDER_UNAVAILABLE,
                reasonCode);
    }

    public boolean redirectSecurityFlowRouteFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AccountMergeFailureCode accountMergeReason,
            IdentityLinkFailureCode identityLinkReason)
            throws IOException {
        var session = request.getSession(false);
        var accountMergeFlow = accountMergeSessionManager
                .consumeFailedBrowserFlow(session);
        if (accountMergeFlow.isPresent()) {
            oauthLoginFlowService.consumeReturnTo(session);
            getRedirectStrategy().sendRedirect(
                    request,
                    response,
                    accountMergeFailureTarget(
                            accountMergeFlow.orElseThrow(),
                            accountMergeReason.name()));
            return true;
        }
        var intentId = identityLinkSessionManager
                .consumeFailedBrowserFlow(session);
        if (intentId.isEmpty()) {
            return false;
        }
        oauthLoginFlowService.consumeReturnTo(session);
        getRedirectStrategy().sendRedirect(
                request,
                response,
                "/settings/security?identityLink=failed"
                        + "&intentId="
                        + intentId.get()
                        + "&reasonCode="
                        + identityLinkReason.name());
        return true;
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception)
            throws IOException, ServletException {
        var session = request.getSession(false);
        String returnTo = oauthLoginFlowService.consumeReturnTo(session);
        var accountMergeFlow = accountMergeSessionManager
                .consumeFailedBrowserFlow(session);
        if (accountMergeFlow.isPresent()) {
            String reasonCode = oauthLoginFlowService
                    .accountMergeFailureReasonCode(exception)
                    .orElse(
                            AccountMergeFailureCode
                                    .MERGE_PROVIDER_AUTHENTICATION_FAILED
                                    .name());
            getRedirectStrategy().sendRedirect(
                    request,
                    response,
                    accountMergeFailureTarget(
                            accountMergeFlow.orElseThrow(),
                            reasonCode));
            return;
        }
        String reasonCode = oauthLoginFlowService
                .identityLinkFailureReasonCode(exception)
                .orElse(
                        IdentityLinkFailureCode
                                .PROVIDER_AUTHENTICATION_FAILED
                                .name());
        String redirectTarget = identityLinkSessionManager
                .consumeFailedBrowserFlow(session)
                .map(intentId ->
                        "/settings/security?identityLink=failed"
                                + "&intentId="
                                + intentId
                                + "&reasonCode="
                                + reasonCode)
                .orElseGet(() ->
                        oauthLoginFlowService.resolveFailureRedirect(
                                exception,
                                returnTo));
        if (redirectTarget != null) {
            getRedirectStrategy().sendRedirect(request, response, redirectTarget);
            return;
        }

        super.onAuthenticationFailure(request, response, exception);
    }

    private String accountMergeFailureTarget(
            AccountMergeBrowserFlowReference flow,
            String reasonCode) {
        return "/settings/accounts?accountMerge=failed"
                + "&phase="
                + flow.phase().name()
                + (flow.intentId() == null
                        ? ""
                        : "&intentId=" + flow.intentId())
                + "&reasonCode="
                + reasonCode;
    }
}
