package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethod;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import com.iflytek.skillhub.auth.oauth.OAuthLoginRedirectSupport;
import com.iflytek.skillhub.config.AuthSessionBootstrapProperties;
import com.iflytek.skillhub.config.DirectAuthProperties;
import com.iflytek.skillhub.dto.AuthMethodResponse;
import com.iflytek.skillhub.dto.AuthProviderResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Builds the catalog of authentication methods and OAuth providers that the UI
 * can render dynamically.
 */
@Service
public class AuthMethodCatalog {

    private final IdentityProviderRegistry identityProviderRegistry;
    private final DirectAuthProperties directAuthProperties;
    private final AuthSessionBootstrapProperties sessionBootstrapProperties;

    public AuthMethodCatalog(IdentityProviderRegistry identityProviderRegistry,
                             DirectAuthProperties directAuthProperties,
                             AuthSessionBootstrapProperties sessionBootstrapProperties) {
        this.identityProviderRegistry = identityProviderRegistry;
        this.directAuthProperties = directAuthProperties;
        this.sessionBootstrapProperties = sessionBootstrapProperties;
    }

    public List<AuthProviderResponse> listOAuthProviders(String returnTo) {
        String sanitizedReturnTo = OAuthLoginRedirectSupport.sanitizeReturnTo(returnTo);
        return new ArrayList<>(identityProviderRegistry.listReadyProviders().stream()
            .sorted(Comparator.comparing(IdentityProviderLoginMethod::providerCode))
            .map(provider -> new AuthProviderResponse(
                provider.providerCode(),
                provider.displayName(),
                buildAuthorizationUrl(provider.providerCode(), sanitizedReturnTo)
            ))
            .toList());
    }

    public List<AuthMethodResponse> listMethods(String returnTo) {
        String sanitizedReturnTo = OAuthLoginRedirectSupport.sanitizeReturnTo(returnTo);
        List<AuthMethodResponse> methods = new ArrayList<>();

        methods.add(new AuthMethodResponse(
            "local-password",
            "PASSWORD",
            "local",
            "Local Account",
            "/api/v1/auth/local/login"
        ));

        if (directAuthProperties.isEnabled()) {
            methods.add(new AuthMethodResponse(
                "direct-local",
                "DIRECT_PASSWORD",
                "local",
                "Local Account",
                "/api/v1/auth/direct/login"
            ));
        }

        identityProviderRegistry.listReadyLoginMethods().stream()
            .filter(this::isMethodEnabled)
            .sorted(Comparator
                .comparing(IdentityProviderLoginMethod::providerCode)
                .thenComparing(IdentityProviderLoginMethod::methodType))
            .forEach(provider -> methods.add(toResponse(
                provider,
                sanitizedReturnTo
            )));

        return methods;
    }

    private boolean isMethodEnabled(IdentityProviderLoginMethod method) {
        return switch (method.methodType()) {
            case OAUTH_REDIRECT -> true;
            case DIRECT_PASSWORD -> directAuthProperties.isEnabled();
            case SESSION_BOOTSTRAP -> sessionBootstrapProperties.isEnabled();
        };
    }

    private AuthMethodResponse toResponse(
            IdentityProviderLoginMethod method,
            String returnTo) {
        String providerCode = method.providerCode();
        return switch (method.methodType()) {
            case OAUTH_REDIRECT -> new AuthMethodResponse(
                "oauth-" + providerCode,
                IdentityProviderLoginMethodType.OAUTH_REDIRECT.name(),
                providerCode,
                method.displayName(),
                buildAuthorizationUrl(providerCode, returnTo)
            );
            case DIRECT_PASSWORD -> new AuthMethodResponse(
                "direct-" + providerCode,
                IdentityProviderLoginMethodType.DIRECT_PASSWORD.name(),
                providerCode,
                method.displayName(),
                "/api/v1/auth/direct/login"
            );
            case SESSION_BOOTSTRAP -> new AuthMethodResponse(
                "bootstrap-" + providerCode,
                IdentityProviderLoginMethodType.SESSION_BOOTSTRAP.name(),
                providerCode,
                method.displayName(),
                "/api/v1/auth/session/bootstrap"
            );
        };
    }

    private String buildAuthorizationUrl(String registrationId, String returnTo) {
        String baseUrl = "/oauth2/authorization/" + registrationId;
        if (returnTo == null) {
            return baseUrl;
        }
        return baseUrl + "?returnTo=" + URLEncoder.encode(returnTo, StandardCharsets.UTF_8);
    }
}
