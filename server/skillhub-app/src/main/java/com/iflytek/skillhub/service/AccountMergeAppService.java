package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityLinkAccountState;
import com.iflytek.skillhub.auth.identity.IdentityLinkBindingView;
import com.iflytek.skillhub.auth.identity.IdentityLinkIntentService;
import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethod;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.local.LocalAuthService;
import com.iflytek.skillhub.auth.merge.AccountMergeActor;
import com.iflytek.skillhub.auth.merge.AccountMergeCompletion;
import com.iflytek.skillhub.auth.merge.AccountMergeException;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
import com.iflytek.skillhub.auth.merge.AccountMergeIntent;
import com.iflytek.skillhub.auth.merge.AccountMergeIntentService;
import com.iflytek.skillhub.auth.merge.AccountMergeMetrics;
import com.iflytek.skillhub.auth.merge.AccountMergePlan;
import com.iflytek.skillhub.auth.merge.AccountMergePrimaryProof;
import com.iflytek.skillhub.auth.merge.AccountMergePreview;
import com.iflytek.skillhub.auth.merge.AccountMergeProviderPrimaryProof;
import com.iflytek.skillhub.auth.merge.AccountMergeProviderProofService;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.dto.AccountMergeAuthenticationMethodResponse;
import com.iflytek.skillhub.dto.AccountMergeBrowserStartResponse;
import com.iflytek.skillhub.dto.AccountMergeCapabilitiesResponse;
import com.iflytek.skillhub.dto.AccountMergeCompletionResponse;
import com.iflytek.skillhub.dto.AccountMergeIntentResponse;
import com.iflytek.skillhub.dto.AccountMergePrimaryProofResponse;
import com.iflytek.skillhub.dto.AccountMergePreviewResponse;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * HTTP-session orchestration for safe account-merge intent creation.
 */
@Service
public class AccountMergeAppService {

    private final AccountMergeIntentService intentService;
    private final LocalAuthService localAuthService;
    private final AccountMergeSessionManager sessionManager;
    private final AccountMergeProviderProofService
            providerProofService;
    private final IdentityProviderRegistry providerRegistry;
    private final ProviderLoginAppService providerLoginAppService;
    private final IdentityLinkIntentService
            identityLinkIntentService;
    private final IdentityLinkSessionManager
            identityLinkSessionManager;
    private final AccountMergeMetrics metrics;
    private final MessageSource messageSource;

    public AccountMergeAppService(
            AccountMergeIntentService intentService,
            LocalAuthService localAuthService,
            AccountMergeSessionManager sessionManager,
            AccountMergeProviderProofService providerProofService,
            IdentityProviderRegistry providerRegistry,
            ProviderLoginAppService providerLoginAppService,
            IdentityLinkIntentService identityLinkIntentService,
            IdentityLinkSessionManager
                    identityLinkSessionManager,
            AccountMergeMetrics metrics,
            MessageSource messageSource) {
        this.intentService = intentService;
        this.localAuthService = localAuthService;
        this.sessionManager = sessionManager;
        this.providerProofService = providerProofService;
        this.providerRegistry = providerRegistry;
        this.providerLoginAppService = providerLoginAppService;
        this.identityLinkIntentService =
                identityLinkIntentService;
        this.identityLinkSessionManager =
                identityLinkSessionManager;
        this.metrics = metrics;
        this.messageSource = messageSource;
    }

    public AccountMergeCapabilitiesResponse capabilities(
            HttpSession session) {
        PlatformPrincipal principal = requirePrincipal(session);
        if (!intentService.isAvailable()) {
            return new AccountMergeCapabilitiesResponse(
                    false,
                    List.of(),
                    List.of());
        }
        return new AccountMergeCapabilitiesResponse(
                true,
                primaryMethods(principal.userId()),
                secondaryMethods());
    }

    public AccountMergePrimaryProofResponse
            reauthenticatePrimaryLocal(
                    String password,
                    HttpSession session) {
        intentService.requireAvailable();
        PlatformPrincipal principal =
                requirePrincipal(session);
        try {
            localAuthService.reauthenticate(
                    principal.userId(),
                    password);
        } catch (AuthFlowException exception) {
            metrics.record(
                    "proof",
                    "primary_local_failure");
            throw new AccountMergeException(
                    AccountMergeFailureCode
                            .MERGE_REAUTH_REQUIRED,
                    exception);
        }
        metrics.record(
                "proof",
                "primary_local_success");
        AccountMergePrimaryProof proof =
                sessionManager.recordPrimaryReauthentication(
                        session,
                        principal.userId(),
                        "local-password");
        return new AccountMergePrimaryProofResponse(
                proof.method(),
                proof.expiresAt());
    }

    public AccountMergeBrowserStartResponse
            reauthenticatePrimaryBrowser(
                    String providerCode,
                    HttpSession session) {
        intentService.requireAvailable();
        PlatformPrincipal principal =
                requirePrincipal(session);
        IdentityProviderLoginMethodType methodType =
                requirePrimaryProviderMethod(
                        principal.userId(),
                        providerCode,
                        Set.of(
                                IdentityProviderLoginMethodType
                                        .OAUTH_REDIRECT,
                                IdentityProviderLoginMethodType
                                        .CAS_REDIRECT));
        identityLinkSessionManager.clearBrowserFlow(session);
        sessionManager.preparePrimaryBrowserFlow(
                session,
                providerCode);
        return new AccountMergeBrowserStartResponse(
                browserAuthorizationUrl(
                        providerCode,
                        methodType,
                        "/settings/accounts"
                                + "?accountMerge=primaryProved"));
    }

    public AccountMergePrimaryProofResponse
            reauthenticatePrimaryCredential(
                    String providerCode,
                    String username,
                    String password,
                    HttpSession session,
                    IdentityLoginContext context) {
        intentService.requireAvailable();
        PlatformPrincipal principal =
                requirePrincipal(session);
        requirePrimaryProviderMethod(
                principal.userId(),
                providerCode,
                Set.of(
                        IdentityProviderLoginMethodType
                                .DIRECT_PASSWORD));
        IdentityProviderRegistry.CredentialRoute route =
                requireCredentialRoute(providerCode);
        AccountMergeProviderPrimaryProof result =
                providerProofService.completePrimary(
                        session,
                        route.provider(),
                        authenticate(
                                route,
                                username,
                                password,
                                context),
                        context);
        return new AccountMergePrimaryProofResponse(
                result.proof().method(),
                result.proof().expiresAt());
    }

    public AccountMergeIntentResponse createIntent(
            HttpSession session,
            IdentityLoginContext context) {
        intentService.requireAvailable();
        UUID intentId = UUID.randomUUID();
        AccountMergeActor actor;
        try {
            actor = sessionManager.startIntent(
                    session,
                    intentId,
                    context);
        } catch (AccountMergeException exception) {
            metrics.record(
                    "proof",
                    exception.getReasonCode()
                            == AccountMergeFailureCode
                                    .MERGE_PROOF_EXPIRED
                            ? "expired"
                            : "primary_failure");
            throw exception;
        }
        try {
            return toResponse(
                    intentService.createIntent(
                            actor,
                            intentId));
        } catch (RuntimeException exception) {
            sessionManager.remove(session, intentId);
            throw exception;
        }
    }

    public AccountMergeIntentResponse
            authenticateSecondaryLocal(
                    UUID intentId,
                    String username,
                    String password,
                    HttpSession session,
                    IdentityLoginContext context) {
        intentService.requireAvailable();
        AccountMergeActor actor = sessionManager.actor(
                session,
                intentId,
                context);
        intentService.getIntent(actor, intentId);
        PlatformPrincipal secondary;
        try {
            secondary = localAuthService.login(
                    username,
                    password);
        } catch (AuthFlowException exception) {
            metrics.record(
                    "proof",
                    "secondary_local_failure");
            throw new AccountMergeException(
                    AccountMergeFailureCode
                            .MERGE_REAUTH_REQUIRED,
                    exception);
        }
        metrics.record(
                "proof",
                "secondary_local_success");
        return toResponse(
                intentService.recordSecondaryProof(
                        actor,
                        intentId,
                        secondary.userId(),
                        "local-password"));
    }

    public AccountMergeBrowserStartResponse
            prepareSecondaryBrowser(
                    UUID intentId,
                    String providerCode,
                    HttpSession session,
                    IdentityLoginContext context) {
        intentService.requireAvailable();
        AccountMergeActor actor = sessionManager.actor(
                session,
                intentId,
                context);
        intentService.getIntent(actor, intentId);
        IdentityProviderLoginMethodType methodType =
                requireReadyBrowserMethod(providerCode);
        identityLinkSessionManager.clearBrowserFlow(session);
        sessionManager.prepareSecondaryBrowserFlow(
                session,
                intentId,
                providerCode,
                context);
        return new AccountMergeBrowserStartResponse(
                browserAuthorizationUrl(
                        providerCode,
                        methodType,
                        "/settings/accounts"
                                + "?accountMerge=secondaryProved"
                                + "&intentId="
                                + intentId));
    }

    public AccountMergeIntentResponse
            authenticateSecondaryCredential(
                    UUID intentId,
                    String providerCode,
                    String username,
                    String password,
                    HttpSession session,
                    IdentityLoginContext context) {
        intentService.requireAvailable();
        AccountMergeActor actor = sessionManager.actor(
                session,
                intentId,
                context);
        intentService.getIntent(actor, intentId);
        IdentityProviderRegistry.CredentialRoute route =
                requireCredentialRoute(providerCode);
        return toResponse(
                providerProofService.completeSecondary(
                        actor,
                        intentId,
                        route.provider(),
                        authenticate(
                                route,
                                username,
                                password,
                                context),
                        context));
    }

    public AccountMergeIntentResponse getIntent(
            UUID intentId,
            HttpSession session,
            IdentityLoginContext context) {
        return toResponse(intentService.getIntent(
                sessionManager.actor(
                        session,
                        intentId,
                        context),
                intentId));
    }

    public AccountMergePreviewResponse preview(
            UUID intentId,
            HttpSession session,
            IdentityLoginContext context) {
        AccountMergePreview preview = intentService.preview(
                sessionManager.actor(
                        session,
                        intentId,
                        context),
                intentId);
        return toResponse(preview);
    }

    public AccountMergeCompletionResponse confirm(
            UUID intentId,
            int previewVersion,
            HttpSession session,
            IdentityLoginContext context) {
        AccountMergeCompletion completion =
                intentService.confirm(
                        sessionManager.actor(
                                session,
                                intentId,
                                context),
                        intentId,
                        previewVersion);
        sessionManager.remove(session, intentId);
        return new AccountMergeCompletionResponse(
                completion.intentId(),
                completion.status(),
                completion.completedAt());
    }

    public AccountMergeIntentResponse cancel(
            UUID intentId,
            HttpSession session,
            IdentityLoginContext context) {
        AccountMergeIntent intent = intentService.cancel(
                sessionManager.actor(
                        session,
                        intentId,
                        context),
                intentId);
        sessionManager.remove(session, intentId);
        return toResponse(intent);
    }

    private PlatformPrincipal requirePrincipal(
            HttpSession session) {
        Object value = session == null
                ? null
                : session.getAttribute("platformPrincipal");
        if (!(value instanceof PlatformPrincipal principal)) {
            throw new AccountMergeException(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        return principal;
    }

    private AccountMergeIntentResponse toResponse(
            AccountMergeIntent intent) {
        return new AccountMergeIntentResponse(
                intent.id(),
                intent.status(),
                intent.expiresAt(),
                secondaryMethods());
    }

    private AccountMergePreviewResponse toResponse(
            AccountMergePreview preview) {
        AccountMergePlan plan = preview.plan();
        return new AccountMergePreviewResponse(
                preview.intentId(),
                preview.status(),
                preview.previewVersion(),
                preview.expiresAt(),
                plan.confirmable(),
                plan.identityProviders(),
                plan.localCredentialAction().name(),
                plan.blockedPlatformRoles(),
                plan.namespaceChanges().stream()
                        .map(change ->
                                new AccountMergePreviewResponse
                                        .NamespaceChange(
                                                change.namespaceId(),
                                                change.namespaceSlug(),
                                                change.primaryRole(),
                                                change.secondaryRole(),
                                                change.resultingRole(),
                                                change.blocked()))
                        .toList(),
                plan.apiTokensToRevoke().stream()
                        .map(token ->
                                new AccountMergePreviewResponse
                                        .ApiToken(
                                                token.name(),
                                                token.prefix()))
                        .toList(),
                plan.skillOwnershipCount(),
                new AccountMergePreviewResponse.SocialSummary(
                        plan.social().starsMoved(),
                        plan.social()
                                .duplicateStarsDiscarded(),
                        plan.social().ratingsMoved(),
                        plan.social()
                                .duplicateRatingsDiscarded(),
                        plan.social().subscriptionsMoved(),
                        plan.social()
                                .duplicateSubscriptionsDiscarded(),
                        plan.social().discardedRatings().stream()
                                .map(rating ->
                                        new AccountMergePreviewResponse
                                                .DiscardedRating(
                                                        rating.skillId(),
                                                        rating.score()))
                                .toList()),
                new AccountMergePreviewResponse
                        .NotificationSummary(
                                plan.notifications()
                                        .notificationsMoved(),
                                plan.notifications()
                                        .preferencesMoved(),
                                plan.notifications()
                                        .duplicatePreferencesDiscarded(),
                                plan.notifications()
                                        .governanceNotificationsMoved()),
                plan.conflicts().stream()
                        .map(conflict ->
                                new AccountMergePreviewResponse
                                        .Conflict(
                                                conflict.code().name(),
                                                conflict.resource(),
                                                conflict.suggestedAction()
                                                        .name()))
                        .toList());
    }

    private List<AccountMergeAuthenticationMethodResponse>
            primaryMethods(String userId) {
        IdentityLinkAccountState state =
                identityLinkIntentService.accountState(userId);
        List<AccountMergeAuthenticationMethodResponse> methods =
                new ArrayList<>();
        if (state.localPasswordEnabled()) {
            methods.add(localPasswordMethod());
        }
        for (IdentityLinkBindingView binding
                : state.linkedProviders()) {
            if (!binding.usable()) {
                continue;
            }
            for (IdentityProviderLoginMethodType methodType
                    : binding.methodTypes()) {
                if (isFreshAuthenticationMethod(methodType)) {
                    methods.add(method(
                            binding.providerCode(),
                            binding.displayName(),
                            methodType));
                }
            }
        }
        return sortedDistinct(methods);
    }

    private List<AccountMergeAuthenticationMethodResponse>
            secondaryMethods() {
        List<AccountMergeAuthenticationMethodResponse> methods =
                new ArrayList<>();
        methods.add(localPasswordMethod());
        for (IdentityProviderLoginMethod method
                : providerRegistry.listReadyLoginMethods()) {
            if (isFreshAuthenticationMethod(
                    method.methodType())) {
                methods.add(method(
                        method.providerCode(),
                        method.displayName(),
                        method.methodType()));
            }
        }
        return sortedDistinct(methods);
    }

    private List<AccountMergeAuthenticationMethodResponse>
            sortedDistinct(
                    List<AccountMergeAuthenticationMethodResponse>
                            methods) {
        Map<String, AccountMergeAuthenticationMethodResponse>
                distinct = new LinkedHashMap<>();
        methods.stream()
                .sorted(Comparator
                        .comparing(
                                AccountMergeAuthenticationMethodResponse
                                        ::providerCode)
                        .thenComparing(
                                AccountMergeAuthenticationMethodResponse
                                        ::methodType))
                .forEach(method -> distinct.putIfAbsent(
                        method.providerCode()
                                + ":"
                                + method.methodType(),
                        method));
        return List.copyOf(distinct.values());
    }

    private AccountMergeAuthenticationMethodResponse
            localPasswordMethod() {
        return new AccountMergeAuthenticationMethodResponse(
                "local",
                messageSource.getMessage(
                        "auth.accountMerge.method.localPassword",
                        null,
                        "Local password",
                        LocaleContextHolder.getLocale()),
                "LOCAL_PASSWORD");
    }

    private AccountMergeAuthenticationMethodResponse method(
            String providerCode,
            String displayName,
            IdentityProviderLoginMethodType methodType) {
        return new AccountMergeAuthenticationMethodResponse(
                providerCode,
                displayName,
                methodType.name());
    }

    private boolean isFreshAuthenticationMethod(
            IdentityProviderLoginMethodType methodType) {
        return methodType
                != IdentityProviderLoginMethodType
                        .SESSION_BOOTSTRAP;
    }

    private IdentityProviderLoginMethodType
            requirePrimaryProviderMethod(
                    String userId,
                    String providerCode,
                    Set<IdentityProviderLoginMethodType>
                            allowedTypes) {
        return identityLinkIntentService.accountState(userId)
                .linkedProviders()
                .stream()
                .filter(IdentityLinkBindingView::usable)
                .filter(binding ->
                        binding.providerCode().equals(
                                providerCode))
                .flatMap(binding ->
                        binding.methodTypes().stream())
                .filter(allowedTypes::contains)
                .sorted()
                .findFirst()
                .orElseThrow(() ->
                        new AccountMergeException(
                                AccountMergeFailureCode
                                        .MERGE_PROVIDER_UNAVAILABLE));
    }

    private IdentityProviderLoginMethodType
            requireReadyBrowserMethod(String providerCode) {
        boolean casAvailable = false;
        for (IdentityProviderLoginMethod method
                : providerRegistry.listReadyLoginMethods()) {
            if (!method.providerCode().equals(providerCode)) {
                continue;
            }
            if (method.methodType()
                    == IdentityProviderLoginMethodType
                            .OAUTH_REDIRECT) {
                return method.methodType();
            }
            if (method.methodType()
                    == IdentityProviderLoginMethodType
                            .CAS_REDIRECT) {
                casAvailable = true;
            }
        }
        if (casAvailable) {
            return IdentityProviderLoginMethodType.CAS_REDIRECT;
        }
        throw new AccountMergeException(
                AccountMergeFailureCode
                        .MERGE_PROVIDER_UNAVAILABLE);
    }

    private IdentityProviderRegistry.CredentialRoute
            requireCredentialRoute(String providerCode) {
        try {
            return providerRegistry.requireCredentialRoute(
                    providerCode);
        } catch (IdentityCoreException exception) {
            throw new AccountMergeException(
                    AccountMergeFailureCode
                            .MERGE_PROVIDER_UNAVAILABLE,
                    exception);
        }
    }

    private com.iflytek.skillhub.auth.identity
            .ProviderAuthenticationResult authenticate(
                    IdentityProviderRegistry.CredentialRoute route,
                    String username,
                    String password,
                    IdentityLoginContext context) {
        try {
            return route.adapter().authenticate(
                    new CredentialAuthenticationRequest(
                            username,
                            password));
        } catch (ProviderAuthenticationException exception) {
            providerLoginAppService.recordProviderAuthenticationFailure(
                    route.provider(),
                    exception,
                    context);
            throw ProviderAuthenticationFailureMapper
                    .mapAccountMerge(exception);
        }
    }

    private String browserAuthorizationUrl(
            String providerCode,
            IdentityProviderLoginMethodType methodType,
            String returnTo) {
        if (methodType
                == IdentityProviderLoginMethodType
                        .OAUTH_REDIRECT) {
            return "/oauth2/authorization/"
                    + providerCode
                    + "?returnTo="
                    + URLEncoder.encode(
                            returnTo,
                            StandardCharsets.UTF_8);
        }
        if (methodType
                == IdentityProviderLoginMethodType
                        .CAS_REDIRECT) {
            return UriComponentsBuilder.fromPath(
                            "/api/v1/auth/cas/"
                                    + "{providerCode}/login")
                    .queryParam("returnTo", returnTo)
                    .buildAndExpand(providerCode)
                    .encode()
                    .toUriString();
        }
        throw new AccountMergeException(
                AccountMergeFailureCode
                        .MERGE_PROVIDER_UNAVAILABLE);
    }
}
