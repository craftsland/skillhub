package com.iflytek.skillhub.exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.merge.AccountMergeException;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.dto.ApiResponse;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.dto.IdentityLinkErrorResponse;
import com.iflytek.skillhub.metrics.SkillHubMetrics;
import com.iflytek.skillhub.observability.RequestIdAccessor;
import com.iflytek.skillhub.security.SensitiveLogSanitizer;
import com.iflytek.skillhub.storage.StorageAccessException;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    private static final String STABLE_USER_ID = "stable-user-123";

    @Mock
    private SensitiveLogSanitizer sensitiveLogSanitizer;

    @Mock
    private SkillHubMetrics metrics;

    @Mock
    private HttpServletRequest request;

    private final Logger logger =
            (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private ListAppender<ILoggingEvent> appender;
    private GlobalExceptionHandler handler;
    private RequestIdAccessor requestIdAccessor;

    @BeforeEach
    void setUp() {
        StaticMessageSource messageSource = new StaticMessageSource();
        messageSource.addMessage("error.request.timeout", java.util.Locale.getDefault(), "Request timed out");
        messageSource.addMessage(
                "error.auth.local.invalidCredentials",
                java.util.Locale.getDefault(),
                "Invalid username or password");
        requestIdAccessor = new RequestIdAccessor();
        ApiResponseFactory responseFactory = new ApiResponseFactory(
                messageSource,
                Clock.fixed(Instant.parse("2026-03-20T00:00:00Z"), ZoneOffset.UTC),
                requestIdAccessor
        );
        handler = new GlobalExceptionHandler(
                responseFactory,
                sensitiveLogSanitizer,
                metrics,
                requestIdAccessor
        );
    }

    @AfterEach
    void tearDown() {
        if (appender != null) {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    @Test
    void handleAsyncRequestTimeout_shouldReturnNoContentForSseRequests() {
        when(request.getRequestURI()).thenReturn("/api/v1/notifications/sse");

        ResponseEntity<?> response = handler.handleAsyncRequestTimeout(new AsyncRequestTimeoutException(), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getBody()).isNull();
    }

    @Test
    void handleAsyncRequestTimeout_shouldReturnApiEnvelopeForNonSseRequests() {
        when(request.getRequestURI()).thenReturn("/api/v1/publish");
        when(request.getMethod()).thenReturn("POST");
        when(sensitiveLogSanitizer.sanitizeRequestTarget(request)).thenReturn("/api/v1/publish");

        ResponseEntity<?> response = handler.handleAsyncRequestTimeout(new AsyncRequestTimeoutException(), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.REQUEST_TIMEOUT);
        assertThat(response.getBody()).isInstanceOf(ApiResponse.class);
        ApiResponse<?> body = (ApiResponse<?>) response.getBody();
        assertThat(body.code()).isEqualTo(408);
        assertThat(body.msg()).isEqualTo("Request timed out");
    }

    @Test
    void handleSessionInvalidated_shouldReturn401ForSessionException() {
        when(request.getMethod()).thenReturn("GET");
        when(sensitiveLogSanitizer.sanitizeRequestTarget(request)).thenReturn("/api/v1/skills");

        IllegalStateException ex = new IllegalStateException("Session was invalidated");
        ResponseEntity<ApiResponse<Void>> response = handler.handleSessionInvalidated(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().code()).isEqualTo(401);
    }

    @Test
    void handleSessionInvalidated_shouldRethrowNonSessionException() {
        IllegalStateException ex = new IllegalStateException("Some other error");

        assertThatThrownBy(() -> handler.handleSessionInvalidated(ex, request))
                .isSameAs(ex);
    }

    @Test
    void handleAuthFailure_shouldUseIdentityLinkReasonCode() {
        String path =
                "/api/v1/auth/identity-link-intents/test"
                        + "/reauthenticate/local";
        when(request.getRequestURI()).thenReturn(path);
        when(request.getMethod()).thenReturn("POST");
        when(sensitiveLogSanitizer
                .sanitizeRequestTarget(request))
                .thenReturn(path);

        ResponseEntity<?> response =
                handler.handleAuthFlowException(
                        new AuthFlowException(
                                HttpStatus.UNAUTHORIZED,
                                "error.auth.local.invalidCredentials"),
                        request);

        assertThat(response.getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody())
                .isInstanceOf(
                        IdentityLinkErrorResponse.class);
        IdentityLinkErrorResponse body =
                (IdentityLinkErrorResponse) response.getBody();
        assertThat(body.reasonCode())
                .isEqualTo("REAUTHENTICATION_REQUIRED");
    }

    @ParameterizedTest
    @EnumSource(value = AccountMergeFailureCode.class, names = {
            "MERGE_REAUTH_REQUIRED", "MERGE_CONFLICT", "ACCOUNT_MERGE_UNAVAILABLE"
    })
    void handleAccountMergeException_shouldLogAuthenticationWithoutStableUserId(
            AccountMergeFailureCode failureCode) {
        authenticateRequest();
        attachAppender();
        when(request.getMethod()).thenReturn("POST");
        when(sensitiveLogSanitizer.sanitizeRequestTarget(request))
                .thenReturn("/api/v1/auth/account-merge/intents/test/confirm");

        try (RequestIdAccessor.Scope ignored = requestIdAccessor.open("request-123")) {
            ResponseEntity<?> response = handler.handleAccountMergeException(
                    new AccountMergeException(failureCode), request);
            assertThat(response.getStatusCode()).isEqualTo(failureCode.status());
        }

        assertThat(loggedMessages()).anySatisfy(message -> assertThat(message)
                .contains("requestId=request-123")
                .contains("status=" + failureCode.status().value())
                .contains("method=POST")
                .contains("path=/api/v1/auth/account-merge/intents/test/confirm")
                .contains("authentication=authenticated")
                .contains("code=" + failureCode.messageCode())
                .doesNotContain(STABLE_USER_ID)
                .doesNotContain("userId="));
    }

    @Test
    void handleGlobalException_shouldLogAuthenticationWithoutStableUserId() {
        authenticateRequest();
        attachAppender();
        when(request.getMethod()).thenReturn("GET");
        when(sensitiveLogSanitizer.sanitizeRequestTarget(request))
                .thenReturn("/api/v1/skills/sensitive");

        try (RequestIdAccessor.Scope ignored = requestIdAccessor.open("request-123")) {
            ResponseEntity<ApiResponse<Void>> response = handler.handleGlobalException(
                    new RuntimeException("boom"), request);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        assertThat(loggedMessages()).anySatisfy(message -> assertThat(message)
                .contains("Unhandled API exception")
                .contains("requestId=request-123")
                .contains("method=GET")
                .contains("path=/api/v1/skills/sensitive")
                .contains("authentication=authenticated")
                .doesNotContain(STABLE_USER_ID)
                .doesNotContain("userId="));
    }

    @Test
    void handleStorageAccess_shouldLogAuthenticationWithoutStableUserId() {
        authenticateRequest();
        attachAppender();
        when(request.getMethod()).thenReturn("GET");
        when(sensitiveLogSanitizer.sanitizeRequestTarget(request))
                .thenReturn("/api/v1/skills/test/download");

        StorageAccessException exception = new StorageAccessException(
                "download", "skills/test.zip", new RuntimeException("unavailable"));
        try (RequestIdAccessor.Scope ignored = requestIdAccessor.open("request-123")) {
            ResponseEntity<ApiResponse<Void>> response = handler.handleStorageAccess(exception, request);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        }

        assertThat(loggedMessages()).anySatisfy(message -> assertThat(message)
                .contains("Object storage unavailable")
                .contains("requestId=request-123")
                .contains("method=GET")
                .contains("path=/api/v1/skills/test/download")
                .contains("authentication=authenticated")
                .contains("operation=download")
                .contains("key=skills/test.zip")
                .doesNotContain(STABLE_USER_ID)
                .doesNotContain("userId="));
    }

    @Test
    void handleAsyncRequestTimeout_shouldLogAnonymousAuthenticationState() {
        attachAppender();
        when(request.getRequestURI()).thenReturn("/api/v1/publish");
        when(request.getMethod()).thenReturn("POST");
        when(sensitiveLogSanitizer.sanitizeRequestTarget(request))
                .thenReturn("/api/v1/publish");

        try (RequestIdAccessor.Scope ignored = requestIdAccessor.open("request-123")) {
            handler.handleAsyncRequestTimeout(new AsyncRequestTimeoutException(), request);
        }

        assertThat(loggedMessages()).anySatisfy(message -> assertThat(message)
                .contains("API request failed")
                .contains("requestId=request-123")
                .contains("status=408")
                .contains("method=POST")
                .contains("path=/api/v1/publish")
                .contains("authentication=anonymous")
                .contains("code=error.request.timeout")
                .doesNotContain("userId="));
    }

    private void authenticateRequest() {
        PlatformPrincipal principal = new PlatformPrincipal(
                STABLE_USER_ID, "User", "user@example.com", null, "local", Set.of("USER"));
        when(request.getUserPrincipal()).thenReturn(
                new UsernamePasswordAuthenticationToken(principal, null, List.of()));
    }

    private void attachAppender() {
        logger.setLevel(Level.INFO);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    private List<String> loggedMessages() {
        return appender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }
}
