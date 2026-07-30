package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityProviderReadinessService;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rejects unavailable OAuth/OIDC routes before Spring Security performs an
 * upstream redirect, token exchange, or user-info request.
 */
public final class IdentityProviderRouteReadinessFilter
        extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(
            IdentityProviderRouteReadinessFilter.class);
    private static final String AUTHORIZATION_PREFIX =
            "/oauth2/authorization/";
    private static final String CALLBACK_PREFIX =
            "/login/oauth2/code/";
    private final ClientRegistrationRepository registrationRepository;
    private final IdentityProviderReadinessService readinessService;
    private final OAuth2LoginFailureHandler failureHandler;

    public IdentityProviderRouteReadinessFilter(
            ClientRegistrationRepository registrationRepository,
            IdentityProviderReadinessService readinessService,
            OAuth2LoginFailureHandler failureHandler) {
        this.registrationRepository = registrationRepository;
        this.readinessService = readinessService;
        this.failureHandler = failureHandler;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = pathWithinApplication(request);
        return !path.startsWith(AUTHORIZATION_PREFIX)
                && !path.startsWith(CALLBACK_PREFIX);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {
        String registrationId = registrationId(request);
        ClientRegistration registration = registrationId == null
                ? null
                : registrationRepository.findByRegistrationId(registrationId);
        if (registration == null) {
            if (redirectIdentityLinkFailure(request, response)) {
                return;
            }
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        try {
            readinessService.requireReady(registration);
        } catch (IdentityCoreException exception) {
            if (redirectIdentityLinkFailure(request, response)) {
                return;
            }
            int status = exception.getReasonCode()
                    == IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH
                    ? HttpServletResponse.SC_SERVICE_UNAVAILABLE
                    : HttpServletResponse.SC_FORBIDDEN;
            log.warn(
                    "Identity provider route '{}' rejected before upstream I/O: {}",
                    registration.getRegistrationId(),
                    exception.getReasonCode());
            response.setStatus(status);
            return;
        } catch (RuntimeException exception) {
            log.error(
                    "Identity provider route '{}' readiness check failed",
                    registration.getRegistrationId(),
                    exception);
            if (redirectIdentityLinkFailure(request, response)) {
                return;
            }
            response.setStatus(
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean redirectIdentityLinkFailure(
            HttpServletRequest request,
            HttpServletResponse response)
            throws IOException {
        return failureHandler.redirectIdentityLinkRouteFailure(
                request,
                response,
                IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);
    }

    private String registrationId(HttpServletRequest request) {
        String path = pathWithinApplication(request);
        String value = pathSegment(path, AUTHORIZATION_PREFIX);
        return value != null
                ? value
                : pathSegment(path, CALLBACK_PREFIX);
    }

    private String pathWithinApplication(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        return contextPath.isEmpty()
                ? requestUri
                : requestUri.substring(contextPath.length());
    }

    private String pathSegment(String path, String prefix) {
        if (!path.startsWith(prefix)) {
            return null;
        }
        String value = path.substring(prefix.length());
        return value.isEmpty() || value.indexOf('/') >= 0
                ? null
                : value;
    }
}
