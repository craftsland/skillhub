package com.iflytek.skillhub.controller;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.dto.AccountMergeBrowserAuthenticationRequest;
import com.iflytek.skillhub.dto.AccountMergeBrowserStartResponse;
import com.iflytek.skillhub.dto.AccountMergeCapabilitiesResponse;
import com.iflytek.skillhub.dto.AccountMergeCompletionResponse;
import com.iflytek.skillhub.dto.AccountMergeConfirmRequest;
import com.iflytek.skillhub.dto.AccountMergeCredentialAuthenticationRequest;
import com.iflytek.skillhub.dto.AccountMergeIntentResponse;
import com.iflytek.skillhub.dto.AccountMergeLocalReauthenticationRequest;
import com.iflytek.skillhub.dto.AccountMergePrimaryProofResponse;
import com.iflytek.skillhub.dto.AccountMergePreviewResponse;
import com.iflytek.skillhub.dto.AccountMergeSecondaryLocalAuthenticationRequest;
import com.iflytek.skillhub.dto.ApiResponse;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.dto.MergeInitiateRequest;
import com.iflytek.skillhub.dto.MergeInitiateResponse;
import com.iflytek.skillhub.dto.MergeVerifyRequest;
import com.iflytek.skillhub.dto.MessageResponse;
import com.iflytek.skillhub.exception.UnauthorizedException;
import com.iflytek.skillhub.ratelimit.RateLimit;
import com.iflytek.skillhub.service.AccountMergeAppService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Safe account-merge resources plus fail-closed compatibility endpoints.
 *
 * <p>The legacy initiate/verify/confirm flow returned the secondary-account verification token to
 * the primary-account session and therefore did not prove independent control of both accounts.
 * Those three routes remain stable but always fail closed; only the fresh-reauthentication and
 * intent resources can perform a merge when the release gate is enabled.
 */
@RestController
@RequestMapping("/api/v1/account/merge")
public class AccountMergeController extends BaseApiController {

    private final AccountMergeAppService accountMergeAppService;

    public AccountMergeController(
            ApiResponseFactory responseFactory,
            AccountMergeAppService accountMergeAppService) {
        super(responseFactory);
        this.accountMergeAppService = accountMergeAppService;
    }

    @Operation(
            summary =
                    "List safe account-merge authentication methods")
    @AccountMergeMutationResponses
    @GetMapping("/capabilities")
    public ApiResponse<AccountMergeCapabilitiesResponse>
            capabilities(HttpServletRequest request) {
        return ok(
                "response.success",
                accountMergeAppService.capabilities(
                        requireSession(request)));
    }

    @Operation(
            summary =
                    "Freshly reauthenticate the primary account"
                            + " with its local password")
    @AccountMergeMutationResponses
    @PostMapping("/reauthenticate/local")
    @RateLimit(
            category = "account-merge-primary-local-reauth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergePrimaryProofResponse>
            reauthenticatePrimaryLocal(
                    @Valid @RequestBody
                            AccountMergeLocalReauthenticationRequest
                                    request,
                    HttpServletRequest servletRequest) {
        return ok(
                "response.success.updated",
                accountMergeAppService
                        .reauthenticatePrimaryLocal(
                                request.password(),
                                requireSession(servletRequest)));
    }

    @Operation(
            summary =
                    "Start primary fresh authentication"
                            + " through a browser provider")
    @AccountMergeMutationResponses
    @PostMapping("/reauthenticate/browser")
    @RateLimit(
            category = "account-merge-primary-browser-reauth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergeBrowserStartResponse>
            reauthenticatePrimaryBrowser(
                    @Valid @RequestBody
                            AccountMergeBrowserAuthenticationRequest
                                    body,
                    HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService
                        .reauthenticatePrimaryBrowser(
                                body.providerCode(),
                                requireSession(request)));
    }

    @Operation(
            summary =
                    "Freshly authenticate the primary account"
                            + " through a credential provider")
    @AccountMergeMutationResponses
    @PostMapping("/reauthenticate/credential")
    @RateLimit(
            category = "account-merge-primary-credential-reauth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergePrimaryProofResponse>
            reauthenticatePrimaryCredential(
                    @Valid @RequestBody
                            AccountMergeCredentialAuthenticationRequest
                                    body,
                    HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService
                        .reauthenticatePrimaryCredential(
                                body.providerCode(),
                                body.username(),
                                body.password(),
                                requireSession(request),
                                context(request)));
    }

    @Operation(summary = "Create a safe account-merge intent")
    @AccountMergeMutationResponses
    @PostMapping("/intents")
    @RateLimit(
            category = "account-merge-intent-create",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergeIntentResponse> createIntent(
            HttpServletRequest request) {
        return ok(
                "response.success.created",
                accountMergeAppService.createIntent(
                        requireSession(request),
                        context(request)));
    }

    @Operation(
            summary =
                    "Prove control of the secondary local account")
    @AccountMergeMutationResponses
    @PostMapping(
            "/intents/{intentId}/secondary-auth/local")
    @RateLimit(
            category = "account-merge-secondary-local-auth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergeIntentResponse>
            authenticateSecondaryLocal(
                    @PathVariable UUID intentId,
                    @Valid @RequestBody
                            AccountMergeSecondaryLocalAuthenticationRequest
                                    body,
                    HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService
                        .authenticateSecondaryLocal(
                                intentId,
                                body.username(),
                                body.password(),
                                requireSession(request),
                                context(request)));
    }

    @Operation(
            summary =
                    "Start independent secondary authentication"
                            + " through a browser provider")
    @AccountMergeMutationResponses
    @PostMapping(
            "/intents/{intentId}/secondary-auth/browser")
    @RateLimit(
            category = "account-merge-secondary-browser-auth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergeBrowserStartResponse>
            prepareSecondaryBrowser(
                    @PathVariable UUID intentId,
                    @Valid @RequestBody
                            AccountMergeBrowserAuthenticationRequest
                                    body,
                    HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService
                        .prepareSecondaryBrowser(
                                intentId,
                                body.providerCode(),
                                requireSession(request),
                                context(request)));
    }

    @Operation(
            summary =
                    "Independently authenticate the secondary"
                            + " through a credential provider")
    @AccountMergeMutationResponses
    @PostMapping(
            "/intents/{intentId}/secondary-auth/credential")
    @RateLimit(
            category = "account-merge-secondary-credential-auth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergeIntentResponse>
            authenticateSecondaryCredential(
                    @PathVariable UUID intentId,
                    @Valid @RequestBody
                            AccountMergeCredentialAuthenticationRequest
                                    body,
                    HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService
                        .authenticateSecondaryCredential(
                                intentId,
                                body.providerCode(),
                                body.username(),
                                body.password(),
                                requireSession(request),
                                context(request)));
    }

    @Operation(summary = "Read the current safe account-merge intent")
    @AccountMergeMutationResponses
    @GetMapping("/intents/{intentId}")
    public ApiResponse<AccountMergeIntentResponse> getIntent(
            @PathVariable UUID intentId,
            HttpServletRequest request) {
        return ok(
                "response.success",
                accountMergeAppService.getIntent(
                        intentId,
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Build a versioned account-merge preview")
    @AccountMergeMutationResponses
    @PostMapping("/intents/{intentId}/preview")
    @RateLimit(
            category = "account-merge-preview",
            authenticated = 10,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergePreviewResponse> preview(
            @PathVariable UUID intentId,
            HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService.preview(
                        intentId,
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Confirm an unchanged account-merge preview")
    @AccountMergeMutationResponses
    @PostMapping("/intents/{intentId}/confirm")
    @RateLimit(
            category = "account-merge-confirm",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<AccountMergeCompletionResponse> confirm(
            @PathVariable UUID intentId,
            @Valid @RequestBody AccountMergeConfirmRequest body,
            HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService.confirm(
                        intentId,
                        body.previewVersion(),
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Cancel an active account-merge intent")
    @AccountMergeMutationResponses
    @DeleteMapping("/intents/{intentId}")
    public ApiResponse<AccountMergeIntentResponse> cancel(
            @PathVariable UUID intentId,
            HttpServletRequest request) {
        return ok(
                "response.success.updated",
                accountMergeAppService.cancel(
                        intentId,
                        requireSession(request),
                        context(request)));
    }

    @PostMapping("/initiate")
    public ApiResponse<MergeInitiateResponse> initiate(@AuthenticationPrincipal PlatformPrincipal principal,
                                                       @Valid @RequestBody MergeInitiateRequest request) {
        if (principal == null) {
            throw new UnauthorizedException("error.auth.required");
        }
        throw mergeTemporarilyUnavailable();
    }

    @PostMapping("/verify")
    public ApiResponse<MessageResponse> verify(@AuthenticationPrincipal PlatformPrincipal principal,
                                               @Valid @RequestBody MergeVerifyRequest request) {
        if (principal == null) {
            throw new UnauthorizedException("error.auth.required");
        }
        throw mergeTemporarilyUnavailable();
    }

    @PostMapping("/confirm")
    public ApiResponse<MessageResponse> confirm(@AuthenticationPrincipal PlatformPrincipal principal,
                                                @Valid @RequestBody ConfirmMergeRequest request) {
        if (principal == null) {
            throw new UnauthorizedException("error.auth.required");
        }
        throw mergeTemporarilyUnavailable();
    }

    public record ConfirmMergeRequest(@jakarta.validation.constraints.NotNull Long mergeRequestId) {}

    private AuthFlowException mergeTemporarilyUnavailable() {
        return new AuthFlowException(
            HttpStatus.SERVICE_UNAVAILABLE,
            "error.auth.merge.temporarilyUnavailable"
        );
    }

    private HttpSession requireSession(
            HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null
                || !(session.getAttribute("platformPrincipal")
                instanceof PlatformPrincipal)) {
            throw new UnauthorizedException(
                    "error.auth.required");
        }
        return session;
    }

    private IdentityLoginContext context(
            HttpServletRequest request) {
        return new IdentityLoginContext(
                bounded(MDC.get("requestId"), 64),
                bounded(request.getRemoteAddr(), 64),
                bounded(
                        request.getHeader("User-Agent"),
                        512));
    }

    private String bounded(
            String value,
            int maximumLength) {
        return value == null
                || value.length() > maximumLength
                ? null
                : value;
    }
}
