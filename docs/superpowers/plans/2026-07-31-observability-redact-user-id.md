# Generic Exception Log User ID Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep generic exception logs diagnostically useful while replacing stable user IDs with a low-cardinality authenticated/anonymous state.

**Architecture:** Limit the production change to `GlobalExceptionHandler`: all three generic exception log templates call one private authentication-state resolver and never format principal names. Capture the class logger in focused unit tests so assertions cover the final formatted messages while API responses, audit records, and metrics remain untouched.

**Tech Stack:** Java 21, Spring Boot 3.2, Spring Security, SLF4J/Logback, JUnit 5, Mockito, AssertJ, Maven.

---

## File map

- Modify `server/skillhub-app/src/main/java/com/iflytek/skillhub/exception/GlobalExceptionHandler.java`: replace raw user attribution in handled, unhandled, and storage failure logs with authentication state.
- Modify `server/skillhub-app/src/test/java/com/iflytek/skillhub/exception/GlobalExceptionHandlerTest.java`: capture formatted Logback messages and cover authenticated, anonymous, and account-merge failure paths.

### Task 1: Prove stable IDs leak from generic exception logs

**Files:**
- Test: `server/skillhub-app/src/test/java/com/iflytek/skillhub/exception/GlobalExceptionHandlerTest.java`

- [ ] **Step 1: Add reusable log capture and authenticated request fixtures**

Add a Logback `ListAppender<ILoggingEvent>`, detach it in `@AfterEach`, retain the `RequestIdAccessor` created in `setUp`, and create an authenticated request with a `PlatformPrincipal` whose ID is `stable-user-123`:

```java
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.iflytek.skillhub.auth.merge.AccountMergeException;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.storage.StorageAccessException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

private static final String STABLE_USER_ID = "stable-user-123";
private final Logger logger =
        (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
private ListAppender<ILoggingEvent> appender;
private RequestIdAccessor requestIdAccessor;

@AfterEach
void tearDown() {
    if (appender != null) {
        logger.detachAppender(appender);
        appender.stop();
    }
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
```

In `setUp`, replace the local declaration with the retained field assignment:

```java
requestIdAccessor = new RequestIdAccessor();
```

- [ ] **Step 2: Add failing tests for handled, unhandled, storage, and anonymous paths**

Use `requestIdAccessor.open("request-123")` around each handler invocation. Assert the relevant formatted message contains the unchanged diagnosis fields plus `authentication=authenticated` or `authentication=anonymous`, and does not contain `STABLE_USER_ID` or `userId=`. Parameterize account-merge handling with `MERGE_REAUTH_REQUIRED`, `MERGE_CONFLICT`, and `ACCOUNT_MERGE_UNAVAILABLE` to cover 401, 409, and 503 responses:

```java
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
```

Add these focused tests for the other two templates and the anonymous state:

```java
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
```

- [ ] **Step 3: Run the focused test and verify RED**

Run:

```bash
cd server && ./mvnw -pl skillhub-app -am -Dtest=GlobalExceptionHandlerTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: the new log assertions fail because production messages still contain `userId=stable-user-123` and do not contain `authentication=authenticated`.

### Task 2: Replace raw user attribution with authentication state

**Files:**
- Modify: `server/skillhub-app/src/main/java/com/iflytek/skillhub/exception/GlobalExceptionHandler.java`
- Test: `server/skillhub-app/src/test/java/com/iflytek/skillhub/exception/GlobalExceptionHandlerTest.java`

- [ ] **Step 1: Change the three log templates and shared resolver**

Remove the unused `PlatformPrincipal` import. In object-storage, unhandled, and handled-exception messages, replace `userId={}` with `authentication={}` and replace `resolveUserId(request)` with `resolveAuthenticationState(request)`. Implement only the low-cardinality resolver:

```java
private String resolveAuthenticationState(HttpServletRequest request) {
    if (request.getUserPrincipal() instanceof Authentication authentication
            && authentication.isAuthenticated()) {
        return "authenticated";
    }
    return "anonymous";
}
```

- [ ] **Step 2: Run the focused test and verify GREEN**

Run:

```bash
cd server && ./mvnw -pl skillhub-app -am -Dtest=GlobalExceptionHandlerTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: `GlobalExceptionHandlerTest` passes; account-merge responses remain 401, 409, and 503 as parameterized, and all formatted-message assertions pass.

- [ ] **Step 3: Check formatting and unintended scope**

Run:

```bash
git diff --check
git diff -- server/skillhub-app/src/main/java/com/iflytek/skillhub/exception/GlobalExceptionHandler.java server/skillhub-app/src/test/java/com/iflytek/skillhub/exception/GlobalExceptionHandlerTest.java
```

Expected: no whitespace errors; production diff changes only the generic log identity field and helper, while the test diff contains only log-capture fixtures and coverage.

- [ ] **Step 4: Commit the verified fix**

```bash
git add server/skillhub-app/src/main/java/com/iflytek/skillhub/exception/GlobalExceptionHandler.java server/skillhub-app/src/test/java/com/iflytek/skillhub/exception/GlobalExceptionHandlerTest.java
git commit -m "fix(observability): redact generic log user IDs (ISSUE-112)"
```

### Task 3: Run quality gates and prepare review

**Files:**
- Verify only; no planned file changes.

- [ ] **Step 1: Run the required backend gate**

Run:

```bash
make test-backend-app
```

Expected: all `skillhub-app` tests and dependent module tests pass with zero failures and zero errors.

- [ ] **Step 2: Verify no API or generated-contract drift**

Run:

```bash
git diff origin/big-main...HEAD --name-only
```

Expected: only the design, plan, handler, and handler test files appear; no controller, DTO, OpenAPI, generated schema, audit, or metrics files changed, so no API document regeneration is required.

- [ ] **Step 3: Run repository hygiene checks**

Run:

```bash
git status --short --branch
git log --format='%h %s' origin/big-main..HEAD
git diff --check origin/big-main...HEAD
```

Expected: clean worktree; all commits contain `ISSUE-112`; no whitespace errors.

- [ ] **Step 4: Obtain tester and reviewer results**

Route the completed diff through the SkillHub tester quality gate and then the reviewer seven-dimension checklist. Any failure returns to Task 1 or Task 2 and repeats the full backend gate before review.

- [ ] **Step 5: Push the one PM-designated branch and open the one final PR**

Push only `fix/observability-redact-user-id`. Create a PR targeting `big-main` with title `fix(observability): avoid raw user IDs in generic exception logs`, body containing `Closes ISSUE-112`, the test command/results, API documentation status (“no API behavior or contract change”), and security impact. Do not merge the PR or operate on `main`.
