package com.iflytek.skillhub.controller.portal;

import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.controller.BaseApiController;
import com.iflytek.skillhub.controller.support.SkillPackageArchiveExtractor;
import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import com.iflytek.skillhub.domain.skill.SkillVisibility;
import com.iflytek.skillhub.domain.skill.SkillVersionStatus;
import com.iflytek.skillhub.domain.skill.metadata.SkillComplianceAuditDetailFactory;
import com.iflytek.skillhub.domain.skill.service.SkillPublishService;
import com.iflytek.skillhub.domain.skill.validation.PackageEntry;
import com.iflytek.skillhub.dto.ApiResponse;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.dto.PublishResponse;
import jakarta.servlet.http.HttpServletRequest;
import com.iflytek.skillhub.metrics.SkillHubMetrics;
import com.iflytek.skillhub.ratelimit.RateLimit;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Upload endpoints for skill packages.
 *
 * <p>The controller is responsible for archive extraction and request shaping,
 * while the domain service owns all publication validation and state changes.
 */
@RestController
@RequestMapping({"/api/v1/skills", "/api/web/skills"})
public class SkillPublishController extends BaseApiController {

    private final SkillPublishService skillPublishService;
    private final SkillPackageArchiveExtractor skillPackageArchiveExtractor;
    private final SkillHubMetrics skillHubMetrics;
    private final AuditLogService auditLogService;
    private final SkillComplianceAuditDetailFactory complianceAuditDetailFactory =
            new SkillComplianceAuditDetailFactory();

    public SkillPublishController(SkillPublishService skillPublishService,
                                  SkillPackageArchiveExtractor skillPackageArchiveExtractor,
                                  ApiResponseFactory responseFactory,
                                  SkillHubMetrics skillHubMetrics,
                                  AuditLogService auditLogService) {
        super(responseFactory);
        this.skillPublishService = skillPublishService;
        this.skillPackageArchiveExtractor = skillPackageArchiveExtractor;
        this.skillHubMetrics = skillHubMetrics;
        this.auditLogService = auditLogService;
    }

    /**
     * Publishes an uploaded package into the target namespace after archive
     * extraction and visibility parsing.
     */
    @PostMapping("/{namespace}/publish")
    @RateLimit(category = "publish", authenticated = 10, anonymous = 0)
    public ApiResponse<PublishResponse> publish(
            @PathVariable String namespace,
            @RequestParam("file") MultipartFile file,
            @RequestParam("visibility") String visibility,
            @RequestParam(value = "confirmWarnings", defaultValue = "false") boolean confirmWarnings,
            @AuthenticationPrincipal PlatformPrincipal principal,
            HttpServletRequest request) throws IOException {

        SkillVisibility skillVisibility = SkillVisibility.valueOf(visibility.toUpperCase());

        List<PackageEntry> entries;
        List<String> extractionWarnings;
        try {
            SkillPackageArchiveExtractor.ExtractionResult extractionResult =
                    skillPackageArchiveExtractor.extractWithWarnings(file);
            entries = extractionResult.entries();
            extractionWarnings = extractionResult.warnings();
        } catch (IllegalArgumentException e) {
            throw new DomainBadRequestException("error.skill.publish.package.invalid", e.getMessage());
        }

        if (!confirmWarnings && !extractionWarnings.isEmpty()) {
            throw new DomainBadRequestException(
                    "error.skill.publish.precheck.confirmRequired",
                    String.join("\n", extractionWarnings));
        }

        SkillPublishService.PublishResult publishResult = skillPublishService.publishFromEntries(
                namespace,
                entries,
                principal.userId(),
                skillVisibility,
                principal.platformRoles(),
                confirmWarnings
        );

        PublishResponse response = new PublishResponse(
                publishResult.skillId(),
                namespace,
                publishResult.slug(),
                publishResult.version().getVersion(),
                publishResult.version().getStatus().name(),
                publishResult.version().getFileCount(),
                publishResult.version().getTotalSize()
        );
        recordPublishAuditIfLatestPublished(principal.userId(), namespace, publishResult, request);
        skillHubMetrics.incrementSkillPublish(namespace, publishResult.version().getStatus().name());

        return ok("response.success.published", response);
    }

    private void recordPublishAuditIfLatestPublished(String userId,
                                                     String namespace,
                                                     SkillPublishService.PublishResult publishResult,
                                                     HttpServletRequest request) {
        if (publishResult.version().getStatus() != SkillVersionStatus.PUBLISHED) {
            return;
        }

        LinkedHashMap<String, Object> extras = new LinkedHashMap<>();
        extras.put("namespace", namespace);
        extras.put("slug", publishResult.slug());
        auditLogService.record(
                userId,
                "PUBLISH",
                "SKILL_VERSION",
                publishResult.version().getId(),
                null,
                request != null ? request.getRemoteAddr() : null,
                request != null ? request.getHeader("User-Agent") : null,
                complianceAuditDetailFactory.latestPublishedEntered(publishResult.version(), extras)
        );
    }
}
