package com.iflytek.skillhub.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.config.IdentityLinkRouteRequestMatcher;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.observability.RequestIdAccessor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * Converts unauthenticated API access attempts into a consistent JSON 401 response.
 */
@Component
public class ApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(ApiAuthenticationEntryPoint.class);
    private final ObjectMapper objectMapper;
    private final ApiResponseFactory apiResponseFactory;
    private final SensitiveLogSanitizer sensitiveLogSanitizer;
    private final RequestIdAccessor requestIdAccessor;

    public ApiAuthenticationEntryPoint(ObjectMapper objectMapper,
                                       ApiResponseFactory apiResponseFactory,
                                       SensitiveLogSanitizer sensitiveLogSanitizer,
                                       RequestIdAccessor requestIdAccessor) {
        this.objectMapper = objectMapper;
        this.apiResponseFactory = apiResponseFactory;
        this.sensitiveLogSanitizer = sensitiveLogSanitizer;
        this.requestIdAccessor = requestIdAccessor;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        logger.info(
                "Unauthorized API request [requestId={}, method={}, path={}, reason={}]",
                requestIdAccessor.current(),
                request.getMethod(),
                sensitiveLogSanitizer.sanitizeRequestTarget(request),
                authException.getClass().getSimpleName()
        );
        Object body = IdentityLinkRouteRequestMatcher.matches(request)
                ? apiResponseFactory.identityLinkError(
                        401,
                        IdentityLinkFailureCode
                                .REAUTHENTICATION_REQUIRED
                                .messageCode(),
                        IdentityLinkFailureCode
                                .REAUTHENTICATION_REQUIRED
                                .name())
                : apiResponseFactory.error(
                        401,
                        "error.auth.required");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
