package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

/**
 * Spring Security OIDC user-service bridge that normalizes standard OIDC
 * claims and reuses the existing OAuth login policy and identity binding flow.
 */
@Service
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private static final Logger log = LoggerFactory.getLogger(CustomOidcUserService.class);

    private final OAuthLoginFlowService oauthLoginFlowService;
    private final OAuth2UserService<OidcUserRequest, OidcUser> delegate;
    private final OAuthIdentityLoginContextResolver contextResolver;

    @Autowired
    public CustomOidcUserService(
            OAuthLoginFlowService oauthLoginFlowService,
            OAuthIdentityLoginContextResolver contextResolver) {
        this(
                oauthLoginFlowService,
                new OidcUserService(),
                contextResolver);
    }

    CustomOidcUserService(OAuthLoginFlowService oauthLoginFlowService,
                          OAuth2UserService<OidcUserRequest, OidcUser> delegate,
                          OAuthIdentityLoginContextResolver contextResolver) {
        this.oauthLoginFlowService = oauthLoginFlowService;
        this.delegate = delegate;
        this.contextResolver = contextResolver;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest request) throws OAuth2AuthenticationException {
        String registrationId = request.getClientRegistration().getRegistrationId();
        log.debug("OIDC login initiated for registration '{}'", registrationId);
        ResolvedProviderHandle provider =
                oauthLoginFlowService.requireReadyProvider(
                        request.getClientRegistration());
        var loginContext = contextResolver.current();

        OidcUser upstreamUser = delegate.loadUser(request);
        ProviderAuthenticationResult result =
                toProviderAuthenticationResult(request, upstreamUser);
        log.debug(
                "OIDC identity facts extracted - registration: {}, subject type: {}",
                registrationId,
                result.primarySubject().type());

        PlatformPrincipal principal;
        try {
            principal = oauthLoginFlowService.authenticate(
                    provider,
                    result,
                    loginContext);
        } catch (OAuth2AuthenticationException e) {
            log.warn(
                    "OIDC authentication failed for registration '{}': {}",
                    registrationId,
                    e.getError().getErrorCode());
            throw e;
        }
        log.debug("OIDC authentication succeeded - userId: {}, roles: {}",
                principal.userId(), principal.platformRoles());

        Map<String, Object> userInfoClaims = new HashMap<>(upstreamUser.getClaims());
        if (upstreamUser.getUserInfo() != null) {
            userInfoClaims.putAll(upstreamUser.getUserInfo().getClaims());
        }
        userInfoClaims.put("platformPrincipal", principal);
        userInfoClaims.put("providerLogin", principal.userId());

        var authorities = new LinkedHashSet<GrantedAuthority>(upstreamUser.getAuthorities());
        principal.platformRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .forEach(authorities::add);

        return new DefaultOidcUser(
                authorities,
                upstreamUser.getIdToken(),
                new OidcUserInfo(userInfoClaims),
                "providerLogin"
        );
    }

    static ProviderAuthenticationResult toProviderAuthenticationResult(
            OidcUserRequest request,
            OidcUser oidcUser) {
        Map<String, Object> claims = new HashMap<>(oidcUser.getClaims());
        String subject = asString(claims.get("sub"));
        if (subject == null || subject.isBlank()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("missing_sub", "OIDC sub claim is required", null));
        }
        String email = asString(claims.get("email"));
        boolean emailVerified = Boolean.TRUE.equals(claims.get("email_verified"));
        Map<String, List<ProviderAttributeValue>> attributes =
                new LinkedHashMap<>();
        put(attributes, "preferred_username", claims.get("preferred_username"),
                ProviderAttributeTrust.ASSERTED);
        put(attributes, "name", claims.get("name"),
                ProviderAttributeTrust.ASSERTED);
        put(
                attributes,
                "email",
                email,
                emailVerified
                        ? ProviderAttributeTrust.VERIFIED
                        : ProviderAttributeTrust.UNVERIFIED);
        put(attributes, "sub", subject, ProviderAttributeTrust.ASSERTED);
        put(attributes, "picture", claims.get("picture"),
                ProviderAttributeTrust.ASSERTED);
        put(attributes, "avatar_url", claims.get("avatar_url"),
                ProviderAttributeTrust.ASSERTED);

        return new ProviderAuthenticationResult(
                new SubjectCandidate("oidc_sub", subject),
                List.of(),
                attributes,
                new ProtocolAuthenticationEvidence(
                        "oidc",
                        oidcUser.getIdToken().getIssuedAt(),
                        Set.of("oidc_authorization_code")));
    }

    private static String asString(Object value) {
        return value instanceof String str ? str : null;
    }

    private static void put(
            Map<String, List<ProviderAttributeValue>> attributes,
            String key,
            Object rawValue,
            ProviderAttributeTrust trust) {
        if (!(rawValue instanceof String value) || value.isBlank()) {
            return;
        }
        attributes.put(
                key,
                List.of(new ProviderAttributeValue(value, trust)));
    }
}
