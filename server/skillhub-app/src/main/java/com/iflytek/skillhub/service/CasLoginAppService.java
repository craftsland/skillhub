package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.cas.CasAuthenticationExchange;
import com.iflytek.skillhub.auth.cas.CasBrowserClient;
import com.iflytek.skillhub.auth.cas.CasLoginInitiation;
import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.oauth.OAuthLoginRedirectSupport;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.session.PlatformSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Orchestrates the CAS browser flow while keeping the remote ticket exchange
 * outside the unified identity transaction.
 */
@Service
public class CasLoginAppService {

    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    private final IdentityProviderRegistry providerRegistry;
    private final CasBrowserClient protocolClient;
    private final ProviderLoginAppService providerLoginAppService;
    private final PlatformSessionService platformSessionService;
    private final CasLoginStateStore stateStore;
    private final Supplier<String> stateSupplier;

    @Autowired
    public CasLoginAppService(
            IdentityProviderRegistry providerRegistry,
            CasBrowserClient protocolClient,
            ProviderLoginAppService providerLoginAppService,
            PlatformSessionService platformSessionService,
            CasLoginStateStore stateStore) {
        this(
                providerRegistry,
                protocolClient,
                providerLoginAppService,
                platformSessionService,
                stateStore,
                CasLoginAppService::newState);
    }

    CasLoginAppService(
            IdentityProviderRegistry providerRegistry,
            CasBrowserClient protocolClient,
            ProviderLoginAppService providerLoginAppService,
            PlatformSessionService platformSessionService,
            CasLoginStateStore stateStore,
            Supplier<String> stateSupplier) {
        this.providerRegistry = providerRegistry;
        this.protocolClient = protocolClient;
        this.providerLoginAppService = providerLoginAppService;
        this.platformSessionService = platformSessionService;
        this.stateStore = stateStore;
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
        if (ticket == null || ticket.isBlank()) {
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
            PlatformPrincipal principal =
                    providerLoginAppService.authenticate(
                            route.provider(),
                            result,
                            request);
            platformSessionService.establishSession(
                    principal,
                    request);
        } catch (ProviderAuthenticationException exception) {
            throw mapProviderFailure(exception);
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
            stored = stateStore.consume(
                            session.getId(),
                            presentedState)
                    .orElseThrow(() -> failure(
                            CasLoginFailure.INVALID_STATE));
        } catch (CasLoginStateStore.CasLoginStateStoreException exception) {
            throw failure(CasLoginFailure.INTERNAL_ERROR);
        }
        if (!stored.providerCode().equals(providerCode)) {
            throw failure(CasLoginFailure.INVALID_STATE);
        }
        return stored;
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
