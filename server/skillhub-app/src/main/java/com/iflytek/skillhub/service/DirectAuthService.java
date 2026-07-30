package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.local.LocalAuthService;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.config.DirectAuthProperties;
import com.iflytek.skillhub.exception.BadRequestException;
import com.iflytek.skillhub.exception.ForbiddenException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * Dispatches direct-login requests to a configured provider and then binds the
 * resulting principal to the current HTTP session.
 */
@Service
public class DirectAuthService {

    private final DirectAuthProperties properties;
    private final IdentityProviderRegistry providerRegistry;
    private final LocalAuthService localAuthService;
    private final ProviderLoginAppService providerLoginAppService;
    private final SessionBootstrapService sessionBootstrapService;

    public DirectAuthService(DirectAuthProperties properties,
                             IdentityProviderRegistry providerRegistry,
                             LocalAuthService localAuthService,
                             ProviderLoginAppService providerLoginAppService,
                             SessionBootstrapService sessionBootstrapService) {
        this.properties = properties;
        this.providerRegistry = providerRegistry;
        this.localAuthService = localAuthService;
        this.providerLoginAppService = providerLoginAppService;
        this.sessionBootstrapService = sessionBootstrapService;
    }

    public PlatformPrincipal authenticate(String providerCode,
                                          String username,
                                          String password,
                                          HttpServletRequest request) {
        if (!properties.isEnabled()) {
            throw new ForbiddenException("error.auth.direct.disabled");
        }

        PlatformPrincipal principal;
        if ("local".equals(providerCode)) {
            principal = localAuthService.login(username, password);
        } else {
            IdentityProviderRegistry.CredentialRoute route;
            try {
                route = providerRegistry.requireCredentialRoute(providerCode);
            } catch (IdentityCoreException exception) {
                if (exception.getReasonCode()
                        == IdentityFailureCode.PROVIDER_DISABLED) {
                    throw new BadRequestException(
                            "error.auth.direct.providerUnsupported",
                            providerCode);
                }
                throw new AuthFlowException(
                        HttpStatus.SERVICE_UNAVAILABLE,
                        "error.auth.external.providerUnavailable");
            }
            var result = authenticate(
                    route,
                    username,
                    password);
            if (result == null) {
                throw new AuthFlowException(
                        HttpStatus.UNAUTHORIZED,
                        "error.auth.external.invalidAssertion");
            }
            principal = providerLoginAppService.authenticate(
                    route.provider(),
                    result,
                    request);
        }

        sessionBootstrapService.establishSession(principal, request);
        return principal;
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
            throw ProviderAuthenticationFailureMapper.map(exception);
        }
    }
}
