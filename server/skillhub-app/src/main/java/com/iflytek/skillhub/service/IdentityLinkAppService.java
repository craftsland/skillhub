package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import com.iflytek.skillhub.auth.identity.ExternalIdentityLinkService;
import com.iflytek.skillhub.auth.identity.IdentityLinkAccountState;
import com.iflytek.skillhub.auth.identity.IdentityLinkActor;
import com.iflytek.skillhub.auth.identity.IdentityLinkBrowserPhase;
import com.iflytek.skillhub.auth.identity.IdentityLinkException;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLinkIntent;
import com.iflytek.skillhub.auth.identity.IdentityLinkIntentService;
import com.iflytek.skillhub.auth.identity.IdentityLinkOutcome;
import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.dto.IdentityLinkAccountStateResponse;
import com.iflytek.skillhub.dto.IdentityLinkBindingResponse;
import com.iflytek.skillhub.dto.IdentityLinkIntentResponse;
import com.iflytek.skillhub.dto.IdentityLinkProviderResponse;
import jakarta.servlet.http.HttpSession;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Application orchestration for explicit link/unlink workflows. Protocol I/O
 * completes before the identity-core transaction is entered.
 */
@Service
public class IdentityLinkAppService {

    private final IdentityLinkIntentService intentService;
    private final ExternalIdentityLinkService externalLinkService;
    private final IdentityProviderRegistry providerRegistry;
    private final IdentityLinkSessionManager sessionManager;
    private final AccountMergeSessionManager
            accountMergeSessionManager;

    public IdentityLinkAppService(
            IdentityLinkIntentService intentService,
            ExternalIdentityLinkService externalLinkService,
            IdentityProviderRegistry providerRegistry,
            IdentityLinkSessionManager sessionManager,
            AccountMergeSessionManager
                    accountMergeSessionManager) {
        this.intentService = intentService;
        this.externalLinkService = externalLinkService;
        this.providerRegistry = providerRegistry;
        this.sessionManager = sessionManager;
        this.accountMergeSessionManager =
                accountMergeSessionManager;
    }

    public IdentityLinkAccountStateResponse accountState(
            String userId,
            HttpSession session) {
        PlatformPrincipal sessionPrincipal =
                (PlatformPrincipal) session
                        .getAttribute("platformPrincipal");
        if (!sessionPrincipal.userId().equals(userId)) {
            throw new IdentityLinkException(
                    IdentityLinkFailureCode.SESSION_MISMATCH);
        }
        IdentityLinkAccountState state =
                intentService.accountState(userId);
        return new IdentityLinkAccountStateResponse(
                state.localPasswordEnabled(),
                state.linkedProviders().stream()
                        .map(binding ->
                                new IdentityLinkBindingResponse(
                                        binding.bindingId(),
                                        binding.providerCode(),
                                        binding.displayName(),
                                        binding.methodTypes(),
                                        binding.usable(),
                                        binding.canUnlink()))
                        .toList(),
                state.availableProviders().stream()
                        .map(provider ->
                                new IdentityLinkProviderResponse(
                                        provider.providerCode(),
                                        provider.displayName(),
                                        provider.methodTypes()))
                        .toList());
    }

    public IdentityLinkIntentResponse createLinkIntent(
            String providerCode,
            HttpSession session,
            IdentityLoginContext context) {
        UUID intentId = UUID.randomUUID();
        IdentityLinkActor actor = sessionManager.start(
                session,
                intentId,
                context);
        try {
            return toResponse(intentService.createLinkIntent(
                    actor,
                    intentId,
                    providerCode));
        } catch (RuntimeException exception) {
            sessionManager.remove(session, intentId);
            throw exception;
        }
    }

    public IdentityLinkIntentResponse createUnlinkIntent(
            long bindingId,
            HttpSession session,
            IdentityLoginContext context) {
        UUID intentId = UUID.randomUUID();
        IdentityLinkActor actor = sessionManager.start(
                session,
                intentId,
                context);
        try {
            return toResponse(intentService.createUnlinkIntent(
                    actor,
                    intentId,
                    bindingId));
        } catch (RuntimeException exception) {
            sessionManager.remove(session, intentId);
            throw exception;
        }
    }

    public IdentityLinkIntentResponse getIntent(
            UUID intentId,
            HttpSession session,
            IdentityLoginContext context) {
        try {
            return toResponse(intentService.getIntent(
                    sessionManager.actor(
                            session,
                            intentId,
                            context),
                    intentId));
        } catch (IdentityLinkException exception) {
            if (exception.getReasonCode()
                    == IdentityLinkFailureCode.INTENT_EXPIRED
                    || exception.getReasonCode()
                    == IdentityLinkFailureCode.ALREADY_CONSUMED) {
                sessionManager.remove(session, intentId);
            }
            throw exception;
        }
    }

    public IdentityLinkIntentResponse cancel(
            UUID intentId,
            HttpSession session,
            IdentityLoginContext context) {
        IdentityLinkIntentResponse response = toResponse(
                intentService.cancel(
                        sessionManager.actor(
                                session,
                                intentId,
                                context),
                        intentId));
        sessionManager.remove(session, intentId);
        return response;
    }

    public IdentityLinkIntentResponse reauthenticateLocal(
            UUID intentId,
            String password,
            HttpSession session,
            IdentityLoginContext context) {
        return toResponse(intentService.reauthenticateLocal(
                sessionManager.actor(
                        session,
                        intentId,
                        context),
                intentId,
                password));
    }

    public String prepareBrowserReauthentication(
            UUID intentId,
            String providerCode,
            HttpSession session,
            IdentityLoginContext context) {
        IdentityLinkActor actor = sessionManager.actor(
                session,
                intentId,
                context);
        IdentityProviderLoginMethodType browserMethod =
                requireBrowserMethod(providerCode);
        IdentityLinkIntent intent =
                intentService.prepareExternalReauthentication(
                        actor,
                        intentId,
                        providerCode,
                        browserMethod);
        accountMergeSessionManager.clearBrowserFlow(session);
        sessionManager.prepareBrowserFlow(
                session,
                intentId,
                IdentityLinkBrowserPhase.REAUTHENTICATE,
                providerCode,
                context);
        return browserAuthorizationUrl(
                providerCode,
                browserMethod,
                "/settings/security?identityLink=reauthenticated"
                        + "&intentId="
                        + intentId);
    }

    public String prepareBrowserLink(
            UUID intentId,
            HttpSession session,
            IdentityLoginContext context) {
        IdentityLinkActor actor = sessionManager.actor(
                session,
                intentId,
                context);
        IdentityLinkIntent current = intentService.getIntent(
                actor,
                intentId);
        IdentityProviderLoginMethodType browserMethod =
                requireBrowserMethod(current.providerCode());
        IdentityLinkIntent intent = intentService.prepareExternalLink(
                actor,
                intentId,
                browserMethod);
        accountMergeSessionManager.clearBrowserFlow(session);
        sessionManager.prepareBrowserFlow(
                session,
                intentId,
                IdentityLinkBrowserPhase.LINK,
                intent.providerCode(),
                context);
        return browserAuthorizationUrl(
                intent.providerCode(),
                browserMethod,
                "/settings/security?identityLink=linked"
                        + "&intentId="
                        + intentId);
    }

    public IdentityLinkIntentResponse reauthenticateCredential(
            UUID intentId,
            String providerCode,
            String username,
            String password,
            HttpSession session,
            IdentityLoginContext context) {
        IdentityLinkActor actor = sessionManager.actor(
                session,
                intentId,
                context);
        intentService.prepareExternalReauthentication(
                actor,
                intentId,
                providerCode,
                IdentityProviderLoginMethodType.DIRECT_PASSWORD);
        IdentityProviderRegistry.CredentialRoute route =
                providerRegistry.requireCredentialRoute(providerCode);
        IdentityLinkOutcome outcome = externalLinkService.reauthenticate(
                actor,
                intentId,
                route.provider(),
                authenticate(route, username, password));
        if (!(outcome instanceof IdentityLinkOutcome.Reauthenticated)) {
            throw new IllegalStateException(
                    "Credential reauthentication returned an invalid outcome");
        }
        return toResponse(intentService.getIntent(
                actor,
                intentId));
    }

    public IdentityLinkIntentResponse linkCredential(
            UUID intentId,
            String username,
            String password,
            HttpSession session,
            IdentityLoginContext context) {
        IdentityLinkActor actor = sessionManager.actor(
                session,
                intentId,
                context);
        IdentityLinkIntent intent = intentService.prepareExternalLink(
                actor,
                intentId,
                IdentityProviderLoginMethodType.DIRECT_PASSWORD);
        IdentityProviderRegistry.CredentialRoute route =
                providerRegistry.requireCredentialRoute(
                        intent.providerCode());
        IdentityLinkOutcome outcome = externalLinkService.link(
                actor,
                intentId,
                route.provider(),
                authenticate(route, username, password));
        if (!(outcome instanceof IdentityLinkOutcome.Linked)) {
            throw new IllegalStateException(
                    "Credential link returned an invalid outcome");
        }
        sessionManager.remove(session, intentId);
        return new IdentityLinkIntentResponse(
                intent.id(),
                intent.operation(),
                IdentityLinkRequestStatus.COMPLETED,
                intent.providerCode(),
                intent.targetBindingId(),
                intent.expiresAt());
    }

    public IdentityLinkIntentResponse completeUnlink(
            UUID intentId,
            HttpSession session,
            IdentityLoginContext context) {
        IdentityLinkIntentResponse response = toResponse(
                intentService.completeUnlink(
                        sessionManager.actor(
                                session,
                                intentId,
                                context),
                        intentId));
        sessionManager.remove(session, intentId);
        return response;
    }

    private ProviderAuthenticationResult authenticate(
            IdentityProviderRegistry.CredentialRoute route,
            String username,
            String password) {
        try {
            return route.adapter().authenticate(
                    new CredentialAuthenticationRequest(
                            username,
                            password));
        } catch (ProviderAuthenticationException exception) {
            throw ProviderAuthenticationFailureMapper
                    .mapIdentityLink(exception);
        }
    }

    private String browserAuthorizationUrl(
            String providerCode,
            IdentityProviderLoginMethodType methodType,
            String returnTo) {
        if (methodType
                == IdentityProviderLoginMethodType.OAUTH_REDIRECT) {
            return "/oauth2/authorization/"
                    + providerCode
                    + "?returnTo="
                    + java.net.URLEncoder.encode(
                            returnTo,
                            java.nio.charset.StandardCharsets.UTF_8);
        }
        if (methodType
                == IdentityProviderLoginMethodType.CAS_REDIRECT) {
            return UriComponentsBuilder
                    .fromPath(
                            "/api/v1/auth/cas/{providerCode}/login")
                    .queryParam("returnTo", returnTo)
                    .buildAndExpand(providerCode)
                    .encode()
                    .toUriString();
        }
        throw new IdentityLinkException(
                IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
    }

    private IdentityProviderLoginMethodType requireBrowserMethod(
            String providerCode) {
        boolean casAvailable = false;
        for (var method : providerRegistry.listReadyLoginMethods()) {
            if (!method.providerCode().equals(providerCode)) {
                continue;
            }
            if (method.methodType()
                    == IdentityProviderLoginMethodType.OAUTH_REDIRECT) {
                return IdentityProviderLoginMethodType.OAUTH_REDIRECT;
            }
            if (method.methodType()
                    == IdentityProviderLoginMethodType.CAS_REDIRECT) {
                casAvailable = true;
            }
        }
        if (casAvailable) {
            return IdentityProviderLoginMethodType.CAS_REDIRECT;
        }
        throw new IdentityLinkException(
                IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
    }

    private IdentityLinkIntentResponse toResponse(
            IdentityLinkIntent intent) {
        return new IdentityLinkIntentResponse(
                intent.id(),
                intent.operation(),
                intent.status(),
                intent.providerCode(),
                intent.targetBindingId(),
                intent.expiresAt());
    }
}
