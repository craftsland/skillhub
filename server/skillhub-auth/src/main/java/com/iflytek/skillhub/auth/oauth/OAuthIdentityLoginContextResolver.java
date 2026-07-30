package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Extracts bounded, non-sensitive audit metadata from the active OAuth/OIDC
 * callback request.
 */
@Component
class OAuthIdentityLoginContextResolver {

    private static final String REQUEST_ID_MDC_KEY = "requestId";

    IdentityLoginContext current() {
        if (!(RequestContextHolder.getRequestAttributes()
                instanceof ServletRequestAttributes attributes)) {
            return IdentityLoginContext.empty();
        }
        HttpServletRequest request = attributes.getRequest();
        return new IdentityLoginContext(
                bounded(MDC.get(REQUEST_ID_MDC_KEY), 64),
                bounded(request.getRemoteAddr(), 64),
                bounded(request.getHeader("User-Agent"), 512));
    }

    private String bounded(String value, int maximum) {
        return value == null || value.length() > maximum
                ? null
                : value;
    }
}
