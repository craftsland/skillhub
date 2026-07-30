package com.iflytek.skillhub.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.config.IdentityLinkRouteRequestMatcher;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.token.ApiTokenAccessDeniedException;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * Converts authorization failures on API routes into the platform's standard JSON error envelope.
 */
@Component
public class ApiAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger logger = LoggerFactory.getLogger(ApiAccessDeniedHandler.class);
    private final ObjectMapper objectMapper;
    private final ApiResponseFactory apiResponseFactory;
    private final SensitiveLogSanitizer sensitiveLogSanitizer;

    public ApiAccessDeniedHandler(ObjectMapper objectMapper,
                                  ApiResponseFactory apiResponseFactory,
                                  SensitiveLogSanitizer sensitiveLogSanitizer) {
        this.objectMapper = objectMapper;
        this.apiResponseFactory = apiResponseFactory;
        this.sensitiveLogSanitizer = sensitiveLogSanitizer;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        ApiTokenAccessDeniedException apiTokenException =
                accessDeniedException instanceof ApiTokenAccessDeniedException typedException
                        ? typedException
                        : null;
        logger.info(
                "Forbidden API request [requestId={}, method={}, path={}, reason={}, detail={}]",
                MDC.get("requestId"),
                request.getMethod(),
                sensitiveLogSanitizer.sanitizeRequestTarget(request),
                accessDeniedException.getClass().getSimpleName(),
                apiTokenException != null ? apiTokenException.getMessage() : null
        );
        Object body;
        if (apiTokenException != null) {
            body = apiResponseFactory.error(
                    403,
                    apiTokenException.getMessageCode(),
                    apiTokenException.getMessageArgs());
        } else if (IdentityLinkRouteRequestMatcher.matches(request)) {
            body = apiResponseFactory.identityLinkError(
                    403,
                    IdentityLinkFailureCode.SESSION_MISMATCH
                            .messageCode(),
                    IdentityLinkFailureCode.SESSION_MISMATCH
                            .name());
        } else {
            body = apiResponseFactory.error(
                    403,
                    "error.forbidden");
        }
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
