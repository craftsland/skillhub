package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ExternalIdentityLoginService;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityLoginOutcome;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.identity.TrustedProviderRouteResolver;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/**
 * Flow owner for browser OAuth login. It centralizes the stages of remembering
 * the return target, loading provider claims, evaluating access policy,
 * provisioning a platform principal, and resolving the final redirect target.
 */
@Service
public class OAuthLoginFlowService {

    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final Map<String, OAuthClaimsExtractor> extractors;
    private final TrustedProviderRouteResolver providerRouteResolver;
    private final ExternalIdentityLoginService identityLoginService;

    public OAuthLoginFlowService(List<OAuthClaimsExtractor> extractorList,
                                 TrustedProviderRouteResolver providerRouteResolver,
                                 ExternalIdentityLoginService identityLoginService) {
        this.extractors = extractorList.stream()
                .collect(Collectors.toMap(OAuthClaimsExtractor::getProvider, Function.identity()));
        this.providerRouteResolver = providerRouteResolver;
        this.identityLoginService = identityLoginService;
    }

    public AuthenticatedLoginContext loadLoginContext(
            OAuth2UserRequest request,
            IdentityLoginContext context) {
        OAuth2User upstreamUser = delegate.loadUser(request);
        String registrationId = request.getClientRegistration().getRegistrationId();

        OAuthClaimsExtractor extractor = extractors.get(registrationId);
        if (extractor == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider", "Unsupported: " + registrationId, null)
            );
        }

        ProviderAuthenticationResult result =
                extractor.authenticate(new OAuthAuthenticationExchange(
                        request,
                        upstreamUser));
        PlatformPrincipal principal = authenticate(
                request.getClientRegistration(),
                result,
                context);
        return new AuthenticatedLoginContext(upstreamUser, principal);
    }

    public PlatformPrincipal authenticate(
            ClientRegistration registration,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        try {
            ResolvedProviderHandle provider =
                    providerRouteResolver.resolve(registration);
            IdentityLoginOutcome outcome = identityLoginService.authenticate(
                    provider,
                    result,
                    context);
            if (outcome instanceof IdentityLoginOutcome.Authenticated authenticated) {
                return authenticated.principal();
            }
            if (outcome instanceof IdentityLoginOutcome.PendingApproval) {
                throw new AccountPendingException();
            }
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    "link_required",
                    "Additional account verification is required",
                    null));
        } catch (IdentityCoreException exception) {
            throw mapIdentityFailure(exception);
        }
    }

    public void rememberReturnTo(HttpServletRequest request) {
        String returnTo = OAuthLoginRedirectSupport.sanitizeReturnTo(request.getParameter("returnTo"));
        HttpSession session = request.getSession();
        if (returnTo == null) {
            session.removeAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
            return;
        }
        session.setAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE, returnTo);
    }

    public String consumeReturnTo(HttpSession session) {
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
        session.removeAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
        return value instanceof String str ? OAuthLoginRedirectSupport.sanitizeReturnTo(str) : null;
    }

    public String resolveFailureRedirect(AuthenticationException exception, String returnTo) {
        if (exception instanceof AccountPendingException) {
            return "/pending-approval";
        }
        if (exception instanceof AccountDisabledException
                || exception instanceof AccountMergedException
                || exception instanceof SystemAccountLoginException) {
            return "/access-denied";
        }
        if (exception instanceof OAuth2AuthenticationException oauth2Exception
                && "access_denied".equals(oauth2Exception.getError().getErrorCode())) {
            return "/access-denied";
        }
        if (exception instanceof OAuth2AuthenticationException oauth2Exception
                && ("provider_authority_mismatch".equals(
                        oauth2Exception.getError().getErrorCode())
                || "provider_disabled".equals(
                        oauth2Exception.getError().getErrorCode())
                || "invalid_identity_assertion".equals(
                        oauth2Exception.getError().getErrorCode())
                || "link_required".equals(
                        oauth2Exception.getError().getErrorCode()))) {
            return "/access-denied";
        }
        if (returnTo != null) {
            return "/login?returnTo=" + URLEncoder.encode(returnTo, StandardCharsets.UTF_8);
        }
        return null;
    }

    public record AuthenticatedLoginContext(OAuth2User upstreamUser, PlatformPrincipal principal) {
    }

    private AuthenticationException mapIdentityFailure(
            IdentityCoreException exception) {
        return switch (exception.getReasonCode()) {
            case ACCOUNT_PENDING -> new AccountPendingException();
            case ACCOUNT_DISABLED -> new AccountDisabledException();
            case ACCOUNT_MERGED -> new AccountMergedException();
            case SYSTEM_ACCOUNT_FORBIDDEN ->
                    new SystemAccountLoginException();
            case ACCESS_DENIED -> oauthFailure(
                    "access_denied",
                    "Access denied by policy",
                    exception);
            case PROVIDER_AUTHORITY_MISMATCH -> oauthFailure(
                    "provider_authority_mismatch",
                    "Identity provider authority mismatch",
                    exception);
            case PROVIDER_DISABLED -> oauthFailure(
                    "provider_disabled",
                    "Identity provider is unavailable",
                    exception);
            case INVALID_IDENTITY_ASSERTION,
                    IDENTITY_SUBJECT_MISSING,
                    IDENTITY_IDENTIFIER_CONFLICT -> oauthFailure(
                    "invalid_identity_assertion",
                    "External identity assertion was rejected",
                    exception);
        };
    }

    private OAuth2AuthenticationException oauthFailure(
            String code,
            String description,
            RuntimeException cause) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(code, description, null),
                cause);
    }
}
