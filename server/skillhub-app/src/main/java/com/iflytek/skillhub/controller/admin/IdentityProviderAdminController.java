package com.iflytek.skillhub.controller.admin;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.controller.BaseApiController;
import com.iflytek.skillhub.dto.ApiResponse;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.dto.IdentityProviderAuthorityRecoveryResponse;
import com.iflytek.skillhub.service.AuditRequestContext;
import com.iflytek.skillhub.service.IdentityProviderAdminAppService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Super-administrator operations for external identity providers.
 */
@RestController
@RequestMapping("/api/v1/admin/identity-providers")
public class IdentityProviderAdminController extends BaseApiController {

    private final IdentityProviderAdminAppService providerAdminAppService;

    public IdentityProviderAdminController(
            IdentityProviderAdminAppService providerAdminAppService,
            ApiResponseFactory responseFactory) {
        super(responseFactory);
        this.providerAdminAppService = providerAdminAppService;
    }

    @Operation(
            summary = "Recover an identity provider authority lock",
            description = "Restores a provider from AUTHORITY_MISMATCH only when the current "
                    + "trusted configuration matches its pinned authority.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Provider recovered or already ready"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Caller is not a super administrator",
                    content = @Content),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Enabled provider configuration not found",
                    content = @Content),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "409",
                    description = "Current configuration does not match the pinned authority",
                    content = @Content)
    })
    @PostMapping("/{providerCode}/authority/recover")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ApiResponse<IdentityProviderAuthorityRecoveryResponse>
            recoverSameAuthority(
                    @PathVariable String providerCode,
                    @AuthenticationPrincipal PlatformPrincipal principal,
                    HttpServletRequest request) {
        return ok(
                "response.success.updated",
                providerAdminAppService.recoverSameAuthority(
                        providerCode,
                        principal.userId(),
                        AuditRequestContext.from(request)));
    }
}
