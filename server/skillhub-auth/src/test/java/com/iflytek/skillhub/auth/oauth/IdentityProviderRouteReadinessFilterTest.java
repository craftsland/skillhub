package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityProviderReadinessService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class IdentityProviderRouteReadinessFilterTest {

    private ClientRegistrationRepository registrationRepository;
    private IdentityProviderReadinessService readinessService;
    private ClientRegistration registration;
    private IdentityProviderRouteReadinessFilter filter;

    @BeforeEach
    void setUp() {
        registrationRepository = mock(
                ClientRegistrationRepository.class);
        readinessService = mock(
                IdentityProviderReadinessService.class);
        registration = registration();
        when(registrationRepository.findByRegistrationId("github"))
                .thenReturn(registration);
        filter = new IdentityProviderRouteReadinessFilter(
                registrationRepository,
                readinessService);
    }

    @Test
    void readyAuthorizationRouteContinuesToSpringOAuthFilter()
            throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest request = request(
                "/oauth2/authorization/github");
        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(readinessService).requireReady(registration);
        verify(chain).doFilter(request, response);
    }

    @Test
    void mismatchCallbackIsRejectedBeforeTokenExchange()
            throws Exception {
        FilterChain chain = mock(FilterChain.class);
        doThrow(new IdentityCoreException(
                IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH))
                .when(readinessService).requireReady(registration);
        MockHttpServletRequest request = request(
                "/login/oauth2/code/github");
        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(503);
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void disabledAuthorizationRouteIsRejectedBeforeRedirect()
            throws Exception {
        FilterChain chain = mock(FilterChain.class);
        doThrow(new IdentityCoreException(
                IdentityFailureCode.PROVIDER_DISABLED))
                .when(readinessService).requireReady(registration);
        MockHttpServletRequest request = request(
                "/oauth2/authorization/github");
        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void unknownRouteIsRejectedWithoutEnteringOAuthFilter()
            throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest request = request(
                "/oauth2/authorization/unknown");
        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        verify(readinessService, never())
                .requireReady(registration);
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void doesNotMisclassifyDownstreamFailureAsReadinessFailure()
            throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest request = request(
                "/oauth2/authorization/github");
        MockHttpServletResponse response =
                new MockHttpServletResponse();
        doThrow(new IllegalStateException("downstream failure"))
                .when(chain).doFilter(request, response);

        assertThatThrownBy(() ->
                filter.doFilter(request, response, chain))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("downstream failure");
    }

    private static MockHttpServletRequest request(String uri) {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", uri);
        request.setServletPath(uri);
        return request;
    }

    private static ClientRegistration registration() {
        return ClientRegistration.withRegistrationId("github")
                .clientId("client")
                .clientSecret("secret")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(
                        "{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri(
                        "https://github.com/login/oauth/authorize")
                .tokenUri(
                        "https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .userNameAttributeName("id")
                .clientName("GitHub")
                .build();
    }
}
