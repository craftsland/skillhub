package com.iflytek.skillhub.controller;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.dto.ApiResponse;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.dto.CreateIdentityLinkRequest;
import com.iflytek.skillhub.dto.CreateIdentityUnlinkRequest;
import com.iflytek.skillhub.dto.IdentityLinkAccountStateResponse;
import com.iflytek.skillhub.dto.IdentityLinkBrowserStartRequest;
import com.iflytek.skillhub.dto.IdentityLinkBrowserStartResponse;
import com.iflytek.skillhub.dto.IdentityLinkCredentialRequest;
import com.iflytek.skillhub.dto.IdentityLinkIntentResponse;
import com.iflytek.skillhub.dto.IdentityLinkLocalReauthenticationRequest;
import com.iflytek.skillhub.dto.IdentityLinkTargetCredentialRequest;
import com.iflytek.skillhub.exception.UnauthorizedException;
import com.iflytek.skillhub.ratelimit.RateLimit;
import com.iflytek.skillhub.service.IdentityLinkAppService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Transport endpoints for explicit external identity link and safe unlink
 * workflows.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(
        name = "Identity Link",
        description = "Manage login methods with fresh reauthentication")
public class IdentityLinkController extends BaseApiController {

    private final IdentityLinkAppService identityLinkAppService;

    public IdentityLinkController(
            ApiResponseFactory responseFactory,
            IdentityLinkAppService identityLinkAppService) {
        super(responseFactory);
        this.identityLinkAppService = identityLinkAppService;
    }

    @Operation(
            summary = "List linked and available login methods",
            description = "Returns active external bindings and providers that can be linked.")
    @IdentityLinkMutationResponses
    @GetMapping("/identity-links")
    public ApiResponse<IdentityLinkAccountStateResponse> accountState(
            @AuthenticationPrincipal PlatformPrincipal principal,
            HttpServletRequest request) {
        requirePrincipal(principal);
        return ok(
                "response.success.read",
                identityLinkAppService.accountState(
                        principal.userId(),
                        requireSession(request)));
    }

    @Operation(summary = "Create an external identity link intent")
    @IdentityLinkMutationResponses
    @PostMapping("/identity-link-intents/link")
    @RateLimit(
            category = "identity-link-create",
            authenticated = 10,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<IdentityLinkIntentResponse> createLinkIntent(
            @Valid @RequestBody CreateIdentityLinkRequest body,
            HttpServletRequest request) {
        return ok(
                "response.success.created",
                identityLinkAppService.createLinkIntent(
                        body.providerCode(),
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Create an external identity unlink intent")
    @IdentityLinkMutationResponses
    @PostMapping("/identity-link-intents/unlink")
    @RateLimit(
            category = "identity-unlink-create",
            authenticated = 10,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<IdentityLinkIntentResponse> createUnlinkIntent(
            @Valid @RequestBody CreateIdentityUnlinkRequest body,
            HttpServletRequest request) {
        return ok(
                "response.success.created",
                identityLinkAppService.createUnlinkIntent(
                        body.bindingId(),
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Get an identity link intent")
    @IdentityLinkMutationResponses
    @GetMapping("/identity-link-intents/{intentId}")
    public ApiResponse<IdentityLinkIntentResponse> getIntent(
            @PathVariable UUID intentId,
            HttpServletRequest request) {
        return ok(
                "response.success.read",
                identityLinkAppService.getIntent(
                        intentId,
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Cancel an identity link intent")
    @IdentityLinkMutationResponses
    @DeleteMapping("/identity-link-intents/{intentId}")
    public ApiResponse<IdentityLinkIntentResponse> cancel(
            @PathVariable UUID intentId,
            HttpServletRequest request) {
        return ok(
                "response.success.updated",
                identityLinkAppService.cancel(
                        intentId,
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Freshly reauthenticate with the local password")
    @IdentityLinkMutationResponses
    @PostMapping(
            "/identity-link-intents/{intentId}"
                    + "/reauthenticate/local")
    @RateLimit(
            category = "identity-link-local-reauth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<IdentityLinkIntentResponse> reauthenticateLocal(
            @PathVariable UUID intentId,
            @Valid @RequestBody
                    IdentityLinkLocalReauthenticationRequest body,
            HttpServletRequest request) {
        return ok(
                "response.success.updated",
                identityLinkAppService.reauthenticateLocal(
                        intentId,
                        body.password(),
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Start browser-provider fresh reauthentication")
    @IdentityLinkMutationResponses
    @PostMapping(
            "/identity-link-intents/{intentId}"
                    + "/reauthenticate/browser")
    @RateLimit(
            category = "identity-link-browser-reauth",
            authenticated = 10,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<IdentityLinkBrowserStartResponse>
            prepareBrowserReauthentication(
                    @PathVariable UUID intentId,
                    @Valid @RequestBody
                            IdentityLinkBrowserStartRequest body,
                    HttpServletRequest request) {
        return ok(
                "response.success.created",
                new IdentityLinkBrowserStartResponse(
                        identityLinkAppService
                                .prepareBrowserReauthentication(
                                        intentId,
                                        body.providerCode(),
                                        requireSession(request),
                                        context(request))));
    }

    @Operation(summary = "Freshly reauthenticate with a credential provider")
    @IdentityLinkMutationResponses
    @PostMapping(
            "/identity-link-intents/{intentId}"
                    + "/reauthenticate/credential")
    @RateLimit(
            category = "identity-link-credential-reauth",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<IdentityLinkIntentResponse>
            reauthenticateCredential(
                    @PathVariable UUID intentId,
                    @Valid @RequestBody
                            IdentityLinkCredentialRequest body,
                    HttpServletRequest request) {
        return ok(
                "response.success.updated",
                identityLinkAppService.reauthenticateCredential(
                        intentId,
                        body.providerCode(),
                        body.username(),
                        body.password(),
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Start browser authentication for the target identity")
    @IdentityLinkMutationResponses
    @PostMapping(
            "/identity-link-intents/{intentId}/link/browser")
    @RateLimit(
            category = "identity-link-browser-target",
            authenticated = 10,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<IdentityLinkBrowserStartResponse>
            prepareBrowserLink(
                    @PathVariable UUID intentId,
                    HttpServletRequest request) {
        return ok(
                "response.success.created",
                new IdentityLinkBrowserStartResponse(
                        identityLinkAppService.prepareBrowserLink(
                                intentId,
                                requireSession(request),
                                context(request))));
    }

    @Operation(summary = "Authenticate and link a credential-provider identity")
    @IdentityLinkMutationResponses
    @PostMapping(
            "/identity-link-intents/{intentId}"
                    + "/link/credential")
    @RateLimit(
            category = "identity-link-credential-target",
            authenticated = 5,
            anonymous = 1,
            windowSeconds = 300)
    public ApiResponse<IdentityLinkIntentResponse> linkCredential(
            @PathVariable UUID intentId,
            @Valid @RequestBody
                    IdentityLinkTargetCredentialRequest body,
            HttpServletRequest request) {
        return ok(
                "response.success.updated",
                identityLinkAppService.linkCredential(
                        intentId,
                        body.username(),
                        body.password(),
                        requireSession(request),
                        context(request)));
    }

    @Operation(summary = "Complete unlink after fresh reauthentication")
    @IdentityLinkMutationResponses
    @PostMapping(
            "/identity-link-intents/{intentId}/unlink")
    public ApiResponse<IdentityLinkIntentResponse> completeUnlink(
            @PathVariable UUID intentId,
            HttpServletRequest request) {
        return ok(
                "response.success.updated",
                identityLinkAppService.completeUnlink(
                        intentId,
                        requireSession(request),
                        context(request)));
    }

    private void requirePrincipal(PlatformPrincipal principal) {
        if (principal == null) {
            throw new UnauthorizedException(
                    "error.auth.required");
        }
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
                bounded(request.getHeader("User-Agent"), 512));
    }

    private String bounded(String value, int maximumLength) {
        return value == null || value.length() > maximumLength
                ? null
                : value;
    }
}
