package com.iflytek.skillhub.controller.admin;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.controller.BaseApiController;
import com.iflytek.skillhub.dto.ApiResponse;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.dto.IdentityProviderAuthorityRecoveryResponse;
import com.iflytek.skillhub.service.AuditRequestContext;
import com.iflytek.skillhub.service.IdentityProviderAdminAppService;
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
