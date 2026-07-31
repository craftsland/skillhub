package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.cas.CasAuthenticationExchange;
import com.iflytek.skillhub.auth.cas.CasBrowserClient;
import com.iflytek.skillhub.auth.cas.CasLoginInitiation;
import com.iflytek.skillhub.auth.exception.AuthFlowException;
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
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.oauth.OAuthLoginRedirectSupport;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.session.PlatformSessionService;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Orchestrates the CAS browser flow while keeping the remote ticket exchange
 * outside the unified identity transaction.
 */
@Service
public class CasLoginAppService {

    private static final Logger log = LoggerFactory.getLogger(
            CasLoginAppService.class);
    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();
    private static final Pattern PROVIDER_CODE_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");

    private final IdentityProviderRegistry providerRegistry;
    private final CasBrowserClient protocolClient;
    private final ProviderLoginAppService providerLoginAppService;
    private final ExternalIdentityLinkService externalIdentityLinkService;
    private final IdentityLinkSessionManager identityLinkSessionManager;
    private final PlatformSessionService platformSessionService;
    private final CasLoginStateStore stateStore;
    private final AuditLogService auditLogService;
    private final Supplier<String> stateSupplier;

    @Autowired
    public CasLoginAppService(
            IdentityProviderRegistry providerRegistry,
            CasBrowserClient protocolClient,
            ProviderLoginAppService providerLoginAppService,
            ExternalIdentityLinkService externalIdentityLinkService,
            IdentityLinkSessionManager identityLinkSessionManager,
            PlatformSessionService platformSessionService,
            CasLoginStateStore stateStore,
            AuditLogService auditLogService) {
        this(
                providerRegistry,
                protocolClient,
                providerLoginAppService,
                externalIdentityLinkService,
                identityLinkSessionManager,
                platformSessionService,
                stateStore,
                auditLogService,
                CasLoginAppService::newState);
    }

    CasLoginAppService(
            IdentityProviderRegistry providerRegistry,
            CasBrowserClient protocolClient,
            ProviderLoginAppService providerLoginAppService,
            ExternalIdentityLinkService externalIdentityLinkService,
            IdentityLinkSessionManager identityLinkSessionManager,
            PlatformSessionService platformSessionService,
            CasLoginStateStore stateStore,
            AuditLogService auditLogService,
            Supplier<String> stateSupplier) {
        this.providerRegistry = providerRegistry;
        this.protocolClient = protocolClient;
        this.providerLoginAppService = providerLoginAppService;
        this.externalIdentityLinkService = externalIdentityLinkService;
        this.identityLinkSessionManager = identityLinkSessionManager;
        this.platformSessionService = platformSessionService;
        this.stateStore = stateStore;
        this.auditLogService = auditLogService;
        this.stateSupplier = stateSupplier;
    }

    public URI begin(
            String providerCode,
            String returnTo,
            HttpServletRequest request) {
        requireRoute(providerCode);
        HttpSession session = request.getSession(true);
        String state = stateSupplier.get();
        CasLoginInitiation initiation;
        try {
            initiation = protocolClient.begin(
                    providerCode,
                    state);
        } catch (ProviderAuthenticationException exception) {
            throw failure(CasLoginFailure.PROVIDER_UNAVAILABLE);
        }

        try {
            stateStore.save(
                    session.getId(),
                    state,
                    providerCode,
                    initiation.serviceUrl(),
                    OAuthLoginRedirectSupport.sanitizeReturnTo(returnTo),
                    initiation.stateTtl());
            identityLinkSessionManager.activateBrowserFlow(
                    session,
                    providerCode,
                    state);
        } catch (CasLoginStateStore.CasLoginStateStoreException exception) {
            throw failure(CasLoginFailure.INTERNAL_ERROR);
        }
        return initiation.loginUri();
    }

    public String complete(
            String providerCode,
            String ticket,
            String state,
            HttpServletRequest request) {
        CasLoginStateStore.CasLoginState loginState =
                consumeState(providerCode, state, request);
        IdentityLoginContext context = context(request);
        Optional<IdentityLinkBrowserFlow> identityLinkFlow;
        try {
            identityLinkFlow =
                    identityLinkSessionManager.consumeBrowserFlow(
                            request,
                            providerCode,
                            context);
        } catch (IdentityLinkException exception) {
            throw failure(CasLoginFailure.INVALID_STATE);
        }
        if (ticket == null || ticket.isBlank()) {
            if (identityLinkFlow.isPresent()) {
                return identityLinkFailureTarget(
                        identityLinkFlow.orElseThrow().intentId(),
                        IdentityLinkFailureCode
                                .PROVIDER_AUTHENTICATION_FAILED);
            }
            throw failure(CasLoginFailure.TICKET_MISSING);
        }

        IdentityProviderRegistry.BrowserRoute<CasAuthenticationExchange>
                route = requireRoute(providerCode);
        try {
            CasAuthenticationExchange exchange =
                    protocolClient.validate(
                            providerCode,
                            ticket,
                            loginState.serviceUrl());
            var result = route.adapter().authenticate(exchange);
            if (identityLinkFlow.isPresent()) {
                completeIdentityLink(
                        identityLinkFlow.orElseThrow(),
                        route,
                        result,
                        request);
            } else {
                PlatformPrincipal principal =
                        providerLoginAppService.authenticate(
                                route.provider(),
                                result,
                                request);
                platformSessionService.establishSession(
                        principal,
                        request);
            }
        } catch (ProviderAuthenticationException exception) {
            if (exception.getReasonCode()
                    == ProviderAuthenticationFailureCode
                            .REPLAY_DETECTED) {
                recordReplayAudit(
                        providerCode,
                        request,
                        "ticket");
            }
            if (identityLinkFlow.isPresent()) {
                return identityLinkFailureTarget(
                        identityLinkFlow.orElseThrow().intentId(),
                        ProviderAuthenticationFailureMapper
                                .mapIdentityLink(exception)
                                .getReasonCode());
            }
            throw mapProviderFailure(exception);
        } catch (IdentityLinkException exception) {
            if (identityLinkFlow.isPresent()) {
                return identityLinkFailureTarget(
                        identityLinkFlow.orElseThrow().intentId(),
                        exception.getReasonCode());
            }
            throw failure(CasLoginFailure.INTERNAL_ERROR);
        } catch (IdentityCoreException exception) {
            if (identityLinkFlow.isPresent()) {
                return identityLinkFailureTarget(
                        identityLinkFlow.orElseThrow().intentId(),
                        mapIdentityCoreFailure(exception));
            }
            throw failure(CasLoginFailure.INTERNAL_ERROR);
        } catch (AuthFlowException exception) {
            throw mapIdentityFailure(exception);
        }

        String returnTo = OAuthLoginRedirectSupport.sanitizeReturnTo(
                loginState.returnTo());
        return returnTo == null
                ? OAuthLoginRedirectSupport.DEFAULT_TARGET_URL
                : returnTo;
    }

    private IdentityProviderRegistry.BrowserRoute
            <CasAuthenticationExchange> requireRoute(
                    String providerCode) {
        try {
            return providerRegistry.requireBrowserRoute(
                    providerCode,
                    CasAuthenticationExchange.class);
        } catch (IdentityCoreException exception) {
            throw failure(CasLoginFailure.PROVIDER_UNAVAILABLE);
        }
    }

    private CasLoginStateStore.CasLoginState consumeState(
            String providerCode,
            String presentedState,
            HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || presentedState == null) {
            throw failure(CasLoginFailure.INVALID_STATE);
        }
        CasLoginStateStore.CasLoginState stored;
        try {
            CasLoginStateStore.ConsumeResult result =
                    stateStore.consume(
                            session.getId(),
                            presentedState);
            if (result.status()
                    == CasLoginStateStore.ConsumeStatus.REPLAYED) {
                recordReplayAudit(
                        providerCode,
                        request,
                        "state");
                throw failure(
                        CasLoginFailure.REPLAY_DETECTED);
            }
            if (result.status()
                    != CasLoginStateStore.ConsumeStatus.CONSUMED) {
                throw failure(
                        CasLoginFailure.INVALID_STATE);
            }
            stored = result.state();
        } catch (CasLoginStateStore.CasLoginStateStoreException exception) {
            throw failure(CasLoginFailure.INTERNAL_ERROR);
        }
        if (!stored.providerCode().equals(providerCode)) {
            throw failure(CasLoginFailure.INVALID_STATE);
        }
        return stored;
    }

    private void completeIdentityLink(
            IdentityLinkBrowserFlow flow,
            IdentityProviderRegistry.BrowserRoute
                    <CasAuthenticationExchange> route,
            ProviderAuthenticationResult result,
            HttpServletRequest request) {
        IdentityLinkOutcome outcome;
        if (flow.phase()
                == IdentityLinkBrowserPhase.REAUTHENTICATE) {
            outcome = externalIdentityLinkService.reauthenticate(
                    flow.actor(),
                    flow.intentId(),
                    route.provider(),
                    result);
        } else {
            outcome = externalIdentityLinkService.link(
                    flow.actor(),
                    flow.intentId(),
                    route.provider(),
                    result);
        }
        if (outcome instanceof IdentityLinkOutcome.Reauthenticated) {
            return;
        }
        if (outcome instanceof IdentityLinkOutcome.Linked) {
            identityLinkSessionManager.remove(
                    request.getSession(false),
                    flow.intentId());
            return;
        }
        throw new IllegalStateException(
                "Unsupported CAS identity link outcome");
    }

    private IdentityLinkFailureCode mapIdentityCoreFailure(
            IdentityCoreException exception) {
        IdentityFailureCode code = exception.getReasonCode();
        return switch (code) {
            case PROVIDER_DISABLED,
                    PROVIDER_AUTHORITY_MISMATCH ->
                    IdentityLinkFailureCode.PROVIDER_UNAVAILABLE;
            case INVALID_IDENTITY_ASSERTION,
                    IDENTITY_SUBJECT_MISSING,
                    IDENTITY_IDENTIFIER_CONFLICT ->
                    IdentityLinkFailureCode
                            .PROVIDER_AUTHENTICATION_FAILED;
            case ACCESS_DENIED,
                    ACCOUNT_PENDING,
                    ACCOUNT_DISABLED,
                    ACCOUNT_MERGED,
                    SYSTEM_ACCOUNT_FORBIDDEN ->
                    IdentityLinkFailureCode.ACCOUNT_NOT_ELIGIBLE;
        };
    }

    private String identityLinkFailureTarget(
            UUID intentId,
            IdentityLinkFailureCode reasonCode) {
        return "/settings/security?identityLink=failed"
                + "&intentId="
                + intentId
                + "&reasonCode="
                + reasonCode.name();
    }

    private IdentityLoginContext context(
            HttpServletRequest request) {
        return new IdentityLoginContext(
                bounded(MDC.get("requestId"), 64),
                bounded(request.getRemoteAddr(), 64),
                bounded(request.getHeader("User-Agent"), 512));
    }

    private void recordReplayAudit(
            String providerCode,
            HttpServletRequest request,
            String artifact) {
        String safeProvider = providerCode != null
                && PROVIDER_CODE_PATTERN.matcher(providerCode).matches()
                ? providerCode
                : "unresolved";
        try {
            auditLogService.record(
                    null,
                    "IDENTITY_REPLAY_DETECTED",
                    "IDENTITY_PROVIDER",
                    null,
                    bounded(MDC.get("requestId"), 64),
                    bounded(request.getRemoteAddr(), 64),
                    bounded(request.getHeader("User-Agent"), 512),
                    "{\"providerCode\":\""
                            + safeProvider
                            + "\",\"protocol\":\"cas\","
                            + "\"reason\":\"REPLAY_DETECTED\","
                            + "\"artifact\":\""
                            + artifact
                            + "\"}");
        } catch (RuntimeException auditFailure) {
            log.error(
                    "CAS replay audit failed [provider={}, failure={}]",
                    safeProvider,
                    auditFailure.getClass().getSimpleName());
        }
    }

    private String bounded(
            String value,
            int maximumLength) {
        return value == null || value.length() > maximumLength
                ? null
                : value;
    }

    private CasLoginFlowException mapProviderFailure(
            ProviderAuthenticationException exception) {
        ProviderAuthenticationFailureCode code =
                exception.getReasonCode();
        return switch (code) {
            case UPSTREAM_INVALID_CREDENTIALS,
                    REPLAY_DETECTED ->
                    failure(CasLoginFailure.VALIDATION_FAILED);
            case UPSTREAM_ACCESS_DENIED ->
                    failure(CasLoginFailure.ACCESS_DENIED);
            case UPSTREAM_UNAVAILABLE,
                    UPSTREAM_MISCONFIGURED,
                    TLS_VALIDATION_FAILED,
                    UPSTREAM_INVALID_RESPONSE ->
                    failure(CasLoginFailure.PROVIDER_UNAVAILABLE);
        };
    }

    private CasLoginFlowException mapIdentityFailure(
            AuthFlowException exception) {
        return switch (exception.getMessageCode()) {
            case "error.auth.external.accountPending" ->
                    failure(CasLoginFailure.ACCOUNT_PENDING);
            case "error.auth.external.accessDenied" ->
                    failure(CasLoginFailure.ACCESS_DENIED);
            case "error.auth.external.linkRequired" ->
                    failure(CasLoginFailure.LINK_REQUIRED);
            case "error.auth.external.providerUnavailable" ->
                    failure(CasLoginFailure.PROVIDER_UNAVAILABLE);
            case "error.auth.external.invalidAssertion" ->
                    failure(CasLoginFailure.VALIDATION_FAILED);
            default -> failure(CasLoginFailure.INTERNAL_ERROR);
        };
    }

    private CasLoginFlowException failure(
            CasLoginFailure failure) {
        return new CasLoginFlowException(failure);
    }

    private static String newState() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

}
