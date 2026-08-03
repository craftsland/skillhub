package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ExternalIdentityLoginService;
import com.iflytek.skillhub.auth.identity.ExternalIdentityLinkService;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLinkBrowserFlow;
import com.iflytek.skillhub.auth.identity.IdentityLinkBrowserPhase;
import com.iflytek.skillhub.auth.identity.IdentityLinkException;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLinkOutcome;
import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityLoginOutcome;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.identity.TrustedProviderRouteResolver;
import com.iflytek.skillhub.auth.merge.AccountMergeBrowserFlow;
import com.iflytek.skillhub.auth.merge.AccountMergeException;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
import com.iflytek.skillhub.auth.merge.AccountMergeProviderProofService;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Flow owner for browser OAuth login. It centralizes the stages of remembering
 * the return target, loading provider claims, evaluating access policy,
 * provisioning a platform principal, and resolving the final redirect target.
 */
@Service
public class OAuthLoginFlowService {

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;
    private final Map<String, OAuthClaimsExtractor> extractors;
    private final TrustedProviderRouteResolver providerRouteResolver;
    private final ExternalIdentityLoginService identityLoginService;
    private final ExternalIdentityLinkService identityLinkService;
    private final IdentityLinkSessionManager identityLinkSessionManager;
    private final AccountMergeSessionManager
            accountMergeSessionManager;
    private final AccountMergeProviderProofService
            accountMergeProviderProofService;

    public OAuthLoginFlowService(List<OAuthClaimsExtractor> extractorList,
                                 TrustedProviderRouteResolver providerRouteResolver,
                                 ExternalIdentityLoginService identityLoginService,
                                 ExternalIdentityLinkService identityLinkService,
                                 IdentityLinkSessionManager identityLinkSessionManager,
                                 AccountMergeSessionManager accountMergeSessionManager,
                                 AccountMergeProviderProofService
                                         accountMergeProviderProofService) {
        this(
                extractorList,
                providerRouteResolver,
                identityLoginService,
                identityLinkService,
                identityLinkSessionManager,
                accountMergeSessionManager,
                accountMergeProviderProofService,
                new DefaultOAuth2UserService());
    }

    @Autowired
    OAuthLoginFlowService(
            List<OAuthClaimsExtractor> extractorList,
            TrustedProviderRouteResolver providerRouteResolver,
            ExternalIdentityLoginService identityLoginService,
            ExternalIdentityLinkService identityLinkService,
            IdentityLinkSessionManager identityLinkSessionManager,
            AccountMergeSessionManager accountMergeSessionManager,
            AccountMergeProviderProofService
                    accountMergeProviderProofService,
            ProviderAwareOAuth2UserService providerAwareUserService) {
        this(
                extractorList,
                providerRouteResolver,
                identityLoginService,
                identityLinkService,
                identityLinkSessionManager,
                accountMergeSessionManager,
                accountMergeProviderProofService,
                (OAuth2UserService<OAuth2UserRequest, OAuth2User>)
                        providerAwareUserService);
    }

    OAuthLoginFlowService(
            List<OAuthClaimsExtractor> extractorList,
            TrustedProviderRouteResolver providerRouteResolver,
            ExternalIdentityLoginService identityLoginService,
            ExternalIdentityLinkService identityLinkService,
            IdentityLinkSessionManager identityLinkSessionManager,
            AccountMergeSessionManager accountMergeSessionManager,
            AccountMergeProviderProofService
                    accountMergeProviderProofService,
            OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate) {
        this.extractors = extractorList.stream()
                .collect(Collectors.toMap(
                        OAuthClaimsExtractor::getProvider,
                        Function.identity()));
        this.providerRouteResolver = providerRouteResolver;
        this.identityLoginService = identityLoginService;
        this.identityLinkService = identityLinkService;
        this.identityLinkSessionManager = identityLinkSessionManager;
        this.accountMergeSessionManager =
                accountMergeSessionManager;
        this.accountMergeProviderProofService =
                accountMergeProviderProofService;
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    public AuthenticatedLoginContext loadLoginContext(
            OAuth2UserRequest request,
            IdentityLoginContext context) {
        String registrationId = request.getClientRegistration().getRegistrationId();
        OAuthClaimsExtractor extractor = extractors.get(registrationId);
        if (extractor == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider", "Unsupported: " + registrationId, null)
            );
        }

        ResolvedProviderHandle provider =
                requireReadyProvider(request.getClientRegistration());
        OAuth2User upstreamUser = delegate.loadUser(request);
        ProviderAuthenticationResult result =
                extractor.authenticate(new OAuthAuthenticationExchange(
                        request,
                        upstreamUser));
        PlatformPrincipal principal = authenticate(
                provider,
                result,
                context);
        return new AuthenticatedLoginContext(upstreamUser, principal);
    }

    public ResolvedProviderHandle requireReadyProvider(
            ClientRegistration registration) {
        try {
            return providerRouteResolver.resolve(registration);
        } catch (IdentityCoreException exception) {
            throw mapIdentityFailure(exception);
        }
    }

    public PlatformPrincipal authenticate(
            ClientRegistration registration,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        return authenticate(
                requireReadyProvider(registration),
                result,
                context);
    }

    PlatformPrincipal authenticate(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        try {
            Optional<AccountMergeBrowserFlow> accountMergeFlow =
                    consumeAccountMergeFlow(provider, context);
            if (accountMergeFlow.isPresent()) {
                return authenticateAccountMergeFlow(
                        accountMergeFlow.orElseThrow(),
                        provider,
                        result,
                        context);
            }
            Optional<IdentityLinkBrowserFlow> identityLinkFlow =
                    consumeIdentityLinkFlow(provider, context);
            if (identityLinkFlow.isPresent()) {
                return authenticateIdentityLinkFlow(
                        identityLinkFlow.get(),
                        provider,
                        result);
            }
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
        } catch (IdentityLinkException exception) {
            throw oauthFailure(
                    "identity_link_failed",
                    exception.getReasonCode().name(),
                    exception);
        } catch (AccountMergeException exception) {
            throw oauthFailure(
                    "account_merge_failed",
                    exception.getReasonCode().name(),
                    exception);
        }
    }

    private Optional<AccountMergeBrowserFlow>
            consumeAccountMergeFlow(
                    ResolvedProviderHandle provider,
                    IdentityLoginContext context) {
        if (!(RequestContextHolder.getRequestAttributes()
                instanceof ServletRequestAttributes attributes)) {
            return Optional.empty();
        }
        return accountMergeSessionManager.consumeBrowserFlow(
                attributes.getRequest(),
                provider.providerCode(),
                context);
    }

    private Optional<IdentityLinkBrowserFlow> consumeIdentityLinkFlow(
            ResolvedProviderHandle provider,
            IdentityLoginContext context) {
        if (!(RequestContextHolder.getRequestAttributes()
                instanceof ServletRequestAttributes attributes)) {
            return Optional.empty();
        }
        return identityLinkSessionManager.consumeBrowserFlow(
                attributes.getRequest(),
                provider.providerCode(),
                context);
    }

    private PlatformPrincipal authenticateIdentityLinkFlow(
            IdentityLinkBrowserFlow flow,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result) {
        IdentityLinkOutcome outcome;
        if (flow.phase()
                == IdentityLinkBrowserPhase.REAUTHENTICATE) {
            outcome = identityLinkService.reauthenticate(
                    flow.actor(),
                    flow.intentId(),
                    provider,
                    result);
        } else {
            outcome = identityLinkService.link(
                    flow.actor(),
                    flow.intentId(),
                    provider,
                    result);
        }
        if (outcome
                instanceof IdentityLinkOutcome.Reauthenticated completed) {
            return completed.principal();
        }
        if (outcome instanceof IdentityLinkOutcome.Linked linked) {
            currentRequest().ifPresent(request ->
                    identityLinkSessionManager.remove(
                            request.getSession(false),
                            flow.intentId()));
            return linked.principal();
        }
        throw new IllegalStateException(
                "Unsupported identity link outcome");
    }

    private PlatformPrincipal authenticateAccountMergeFlow(
            AccountMergeBrowserFlow flow,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        HttpSession session = currentRequest()
                .map(request -> request.getSession(false))
                .orElseThrow(() ->
                        new AccountMergeException(
                                AccountMergeFailureCode
                                        .MERGE_SESSION_MISMATCH));
        if (flow instanceof AccountMergeBrowserFlow.Primary) {
            return accountMergeProviderProofService
                    .completePrimary(
                            session,
                            provider,
                            result,
                            context)
                    .principal();
        }
        AccountMergeBrowserFlow.Secondary secondary =
                (AccountMergeBrowserFlow.Secondary) flow;
        accountMergeProviderProofService.completeSecondary(
                secondary.actor(),
                secondary.intentId(),
                provider,
                result,
                context);
        Object principalValue =
                session.getAttribute("platformPrincipal");
        if (!(principalValue
                        instanceof PlatformPrincipal principal)
                || !principal.userId().equals(
                        flow.primaryUserId())) {
            throw new AccountMergeException(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        return principal;
    }

    private Optional<HttpServletRequest> currentRequest() {
        if (RequestContextHolder.getRequestAttributes()
                instanceof ServletRequestAttributes attributes) {
            return Optional.of(attributes.getRequest());
        }
        return Optional.empty();
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
        if (exception instanceof OAuth2AuthenticationException oauth2Exception
                && "account_merge_failed".equals(
                        oauth2Exception.getError().getErrorCode())) {
            return accountMergeFailureRedirect(
                    returnTo,
                    accountMergeFailureReasonCode(exception)
                            .orElse(null));
        }
        if (exception instanceof OAuth2AuthenticationException oauth2Exception
                && "identity_link_failed".equals(
                        oauth2Exception.getError().getErrorCode())) {
            return identityLinkFailureRedirect(
                    returnTo,
                    identityLinkFailureReasonCode(exception)
                            .orElse(null));
        }
        if (returnTo != null) {
            return "/login?returnTo=" + URLEncoder.encode(returnTo, StandardCharsets.UTF_8);
        }
        return null;
    }

    public Optional<String> identityLinkFailureReasonCode(
            AuthenticationException exception) {
        if (!(exception
                instanceof OAuth2AuthenticationException oauth2Exception)
                || !"identity_link_failed".equals(
                        oauth2Exception.getError().getErrorCode())) {
            return Optional.empty();
        }
        String description =
                oauth2Exception.getError().getDescription();
        try {
            return Optional.of(
                    IdentityLinkFailureCode.valueOf(
                            description).name());
        } catch (IllegalArgumentException | NullPointerException ignored) {
            return Optional.empty();
        }
    }

    public Optional<String> accountMergeFailureReasonCode(
            AuthenticationException exception) {
        if (!(exception
                instanceof OAuth2AuthenticationException oauth2Exception)
                || !"account_merge_failed".equals(
                        oauth2Exception.getError().getErrorCode())) {
            return Optional.empty();
        }
        String description =
                oauth2Exception.getError().getDescription();
        try {
            return Optional.of(
                    AccountMergeFailureCode.valueOf(
                            description).name());
        } catch (IllegalArgumentException | NullPointerException ignored) {
            return Optional.empty();
        }
    }

    private String identityLinkFailureRedirect(
            String returnTo,
            String reasonCode) {
        Optional<UUID> intentId = identityLinkIntentId(returnTo);
        return "/settings/security?identityLink=failed"
                + intentId.map(id -> "&intentId=" + id)
                        .orElse("")
                + (reasonCode == null
                        ? ""
                        : "&reasonCode="
                                + URLEncoder.encode(
                                reasonCode,
                                StandardCharsets.UTF_8));
    }

    private String accountMergeFailureRedirect(
            String returnTo,
            String reasonCode) {
        Optional<UUID> intentId =
                accountMergeIntentId(returnTo);
        return "/settings/accounts?accountMerge=failed"
                + intentId.map(id -> "&intentId=" + id)
                        .orElse("")
                + (reasonCode == null
                        ? ""
                        : "&reasonCode="
                                + URLEncoder.encode(
                                        reasonCode,
                                        StandardCharsets.UTF_8));
    }

    private Optional<UUID> identityLinkIntentId(String returnTo) {
        if (returnTo == null
                || !returnTo.startsWith("/settings/security?")) {
            return Optional.empty();
        }
        String query = returnTo.substring(
                returnTo.indexOf('?') + 1);
        for (String parameter : query.split("&")) {
            int separator = parameter.indexOf('=');
            if (separator <= 0
                    || !"intentId".equals(
                            parameter.substring(0, separator))) {
                continue;
            }
            try {
                return Optional.of(UUID.fromString(
                        parameter.substring(separator + 1)));
            } catch (IllegalArgumentException ignored) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private Optional<UUID> accountMergeIntentId(
            String returnTo) {
        if (returnTo == null
                || !returnTo.startsWith(
                        "/settings/accounts?")) {
            return Optional.empty();
        }
        return intentIdParameter(returnTo);
    }

    private Optional<UUID> intentIdParameter(String returnTo) {
        String query = returnTo.substring(
                returnTo.indexOf('?') + 1);
        for (String parameter : query.split("&")) {
            int separator = parameter.indexOf('=');
            if (separator <= 0
                    || !"intentId".equals(
                            parameter.substring(0, separator))) {
                continue;
            }
            try {
                return Optional.of(UUID.fromString(
                        parameter.substring(separator + 1)));
            } catch (IllegalArgumentException ignored) {
                return Optional.empty();
            }
        }
        return Optional.empty();
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
