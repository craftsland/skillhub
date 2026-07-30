package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.session.PlatformSessionService;
import com.iflytek.skillhub.config.AuthSessionBootstrapProperties;
import com.iflytek.skillhub.exception.BadRequestException;
import com.iflytek.skillhub.exception.ForbiddenException;
import com.iflytek.skillhub.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * Restores a platform session from a passive authenticator and persists the
 * resulting principal into Spring Security's session context.
 */
@Service
public class SessionBootstrapService {

    private final AuthSessionBootstrapProperties properties;
    private final IdentityProviderRegistry providerRegistry;
    private final ProviderLoginAppService providerLoginAppService;
    private final PlatformSessionService platformSessionService;

    public SessionBootstrapService(AuthSessionBootstrapProperties properties,
                                   IdentityProviderRegistry providerRegistry,
                                   ProviderLoginAppService providerLoginAppService,
                                   PlatformSessionService platformSessionService) {
        this.properties = properties;
        this.providerRegistry = providerRegistry;
        this.providerLoginAppService = providerLoginAppService;
        this.platformSessionService = platformSessionService;
    }

    public PlatformPrincipal bootstrap(String providerCode, HttpServletRequest request) {
        if (!properties.isEnabled()) {
            throw new ForbiddenException("error.auth.sessionBootstrap.disabled");
        }

        IdentityProviderRegistry.PassiveRoute route;
        try {
            route = providerRegistry.requirePassiveRoute(providerCode);
        } catch (IdentityCoreException exception) {
            if (exception.getReasonCode()
                    == IdentityFailureCode.PROVIDER_DISABLED) {
                throw new BadRequestException(
                        "error.auth.sessionBootstrap.providerUnsupported",
                        providerCode);
            }
            throw new AuthFlowException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "error.auth.external.providerUnavailable");
        }

        var authentication = authenticate(route, request);
        if (authentication == null) {
            throw new AuthFlowException(
                    HttpStatus.UNAUTHORIZED,
                    "error.auth.external.invalidAssertion");
        }
        var result = authentication
                .orElseThrow(() -> new UnauthorizedException(
                        "error.auth.sessionBootstrap.notAuthenticated"));
        PlatformPrincipal principal = providerLoginAppService.authenticate(
                route.provider(),
                result,
                request);
        platformSessionService.establishSession(principal, request);
        return principal;
    }

    private Optional<ProviderAuthenticationResult> authenticate(
            IdentityProviderRegistry.PassiveRoute route,
            HttpServletRequest request) {
        try {
            return route.adapter().authenticate(request);
        } catch (ProviderAuthenticationException exception) {
            throw ProviderAuthenticationFailureMapper.map(exception);
        }
    }

    public void establishSession(PlatformPrincipal principal, HttpServletRequest request) {
        platformSessionService.establishSession(principal, request);
    }
}
