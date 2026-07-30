package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityProviderReadinessService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rejects unavailable OAuth/OIDC routes before Spring Security performs an
 * upstream redirect, token exchange, or user-info request.
 */
public final class IdentityProviderRouteReadinessFilter
        extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(
            IdentityProviderRouteReadinessFilter.class);
    private static final String REGISTRATION_ID = "registrationId";

    private final AntPathRequestMatcher authorizationMatcher =
            new AntPathRequestMatcher(
                    "/oauth2/authorization/{registrationId}");
    private final AntPathRequestMatcher callbackMatcher =
            new AntPathRequestMatcher(
                    "/login/oauth2/code/{registrationId}");
    private final ClientRegistrationRepository registrationRepository;
    private final IdentityProviderReadinessService readinessService;

    public IdentityProviderRouteReadinessFilter(
            ClientRegistrationRepository registrationRepository,
            IdentityProviderReadinessService readinessService) {
        this.registrationRepository = registrationRepository;
        this.readinessService = readinessService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !authorizationMatcher.matches(request)
                && !callbackMatcher.matches(request);
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
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        try {
            readinessService.requireReady(registration);
        } catch (IdentityCoreException exception) {
            int status = exception.getReasonCode()
                    == IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH
                    ? HttpServletResponse.SC_SERVICE_UNAVAILABLE
                    : HttpServletResponse.SC_FORBIDDEN;
            log.warn(
                    "Identity provider route '{}' rejected before upstream I/O: {}",
                    registration.getRegistrationId(),
                    exception.getReasonCode());
            response.sendError(status);
            return;
        } catch (RuntimeException exception) {
            log.error(
                    "Identity provider route '{}' readiness check failed",
                    registration.getRegistrationId(),
                    exception);
            response.sendError(
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private String registrationId(HttpServletRequest request) {
        String value = variable(authorizationMatcher, request);
        return value != null
                ? value
                : variable(callbackMatcher, request);
    }

    private String variable(
            AntPathRequestMatcher matcher,
            HttpServletRequest request) {
        RequestMatcher.MatchResult result = matcher.matcher(request);
        return result.isMatch()
                ? result.getVariables().get(REGISTRATION_ID)
                : null;
    }
}
