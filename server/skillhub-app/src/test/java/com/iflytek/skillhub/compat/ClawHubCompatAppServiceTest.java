package com.iflytek.skillhub.compat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.controller.support.MultipartPackageExtractor;
import com.iflytek.skillhub.controller.support.ZipPackageExtractor;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.namespace.Namespace;
import com.iflytek.skillhub.domain.shared.exception.DomainNotFoundException;
import com.iflytek.skillhub.domain.skill.Skill;
import com.iflytek.skillhub.domain.skill.SkillVersion;
import com.iflytek.skillhub.domain.skill.SkillVersionStatus;
import com.iflytek.skillhub.domain.skill.SkillVisibility;
import com.iflytek.skillhub.domain.skill.service.SkillPublishService;
import com.iflytek.skillhub.domain.skill.service.SkillQueryService;
import com.iflytek.skillhub.domain.skill.validation.PackageEntry;
import com.iflytek.skillhub.domain.social.SkillStarService;
import com.iflytek.skillhub.service.SkillSearchAppService;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;

class ClawHubCompatAppServiceTest {

    private final SkillSearchAppService skillSearchAppService = mock(SkillSearchAppService.class);
    private final SkillQueryService skillQueryService = mock(SkillQueryService.class);
    private final SkillPublishService skillPublishService = mock(SkillPublishService.class);
    private final ZipPackageExtractor zipPackageExtractor = mock(ZipPackageExtractor.class);
    private final MultipartPackageExtractor multipartPackageExtractor = mock(MultipartPackageExtractor.class);
    private final AuditLogService auditLogService = mock(AuditLogService.class);
    private final CompatSkillLookupService compatSkillLookupService = mock(CompatSkillLookupService.class);
    private final SkillStarService skillStarService = mock(SkillStarService.class);

    private final ClawHubCompatAppService service = new ClawHubCompatAppService(
            new CanonicalSlugMapper(),
            skillSearchAppService,
            skillQueryService,
            skillPublishService,
            zipPackageExtractor,
            multipartPackageExtractor,
            auditLogService,
            compatSkillLookupService,
            skillStarService
    );

    @Test
    void downloadLocationByQuery_throwsNotFound_whenLegacySkillIsPrivateForAnonymousCaller() {
        Namespace namespace = new Namespace("team-a", "Team A", "owner-1");
        Skill privateSkill = new Skill(1L, "priv", "owner-1", SkillVisibility.PRIVATE);
        CompatSkillLookupService.CompatSkillContext context = new CompatSkillLookupService.CompatSkillContext(
                namespace,
                privateSkill,
                Optional.empty()
        );

        when(compatSkillLookupService.findByLegacySlug("priv")).thenReturn(context);
        when(compatSkillLookupService.canAccess(privateSkill, null, Map.of())).thenReturn(false);

        assertThatThrownBy(() -> service.downloadLocationByQuery("priv", "latest", null, null))
                .isInstanceOf(DomainNotFoundException.class);
    }

    @Test
    void downloadLocationByQuery_returnsCanonicalPath_whenLegacySkillIsVisible() {
        Namespace namespace = new Namespace("team-a", "Team A", "owner-1");
        Skill publicSkill = new Skill(1L, "my-skill", "owner-1", SkillVisibility.PUBLIC);
        CompatSkillLookupService.CompatSkillContext context = new CompatSkillLookupService.CompatSkillContext(
                namespace,
                publicSkill,
                Optional.empty()
        );

        when(compatSkillLookupService.findByLegacySlug("my-skill")).thenReturn(context);
        when(compatSkillLookupService.canAccess(publicSkill, null, Map.of())).thenReturn(true);

        String location = service.downloadLocationByQuery("my-skill", "latest", null, null);

        assertThat(location).isEqualTo("/api/v1/skills/team-a/my-skill/download");
    }

    @Test
    void publishSkill_recordsComplianceSnapshotWhenLatestPublished() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "files",
                "SKILL.md",
                "text/markdown",
                "name: demo".getBytes()
        );
        MockMultipartFile[] files = new MockMultipartFile[]{file};
        MultipartPackageExtractor.PublishPayload payload = new MultipartPackageExtractor.PublishPayload(
                "team-ai",
                "demo-skill",
                "Demo Skill",
                "1.0.0",
                null,
                true,
                List.of(),
                null
        );
        List<PackageEntry> entries = List.of(
                new PackageEntry("SKILL.md", "name: demo".getBytes(), 10, "text/markdown")
        );
        when(multipartPackageExtractor.extract(files, "{\"slug\":\"demo-skill\"}"))
                .thenReturn(new MultipartPackageExtractor.ExtractedPackage(payload, entries));

        SkillVersion version = publishedVersionWithCompliance(22L, "1.0.0", "CC6.1");
        when(skillPublishService.publishFromEntries(
                "team-ai",
                entries,
                "user-1",
                SkillVisibility.PUBLIC,
                Set.of("SUPER_ADMIN"),
                true
        )).thenReturn(new SkillPublishService.PublishResult(7L, "demo-skill", version));

        PlatformPrincipal principal = new PlatformPrincipal(
                "user-1",
                "publisher",
                "publisher@example.com",
                "",
                "local",
                Set.of("SUPER_ADMIN")
        );

        service.publishSkill(
                "{\"slug\":\"demo-skill\"}",
                files,
                true,
                principal,
                "127.0.0.1",
                "JUnit"
        );

        verify(auditLogService).record(
                eq("user-1"),
                eq("COMPAT_PUBLISH"),
                eq("SKILL_VERSION"),
                eq(22L),
                isNull(),
                eq("127.0.0.1"),
                eq("JUnit"),
                contains("\"snapshotKind\":\"latest_published_entered\"")
        );
        verify(auditLogService).record(
                eq("user-1"),
                eq("COMPAT_PUBLISH"),
                eq("SKILL_VERSION"),
                eq(22L),
                isNull(),
                eq("127.0.0.1"),
                eq("JUnit"),
                contains("\"controlId\":\"CC6.1\"")
        );
    }

    @Test
    void publish_recordsComplianceSnapshotWhenLatestPublished() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "demo.zip",
                "application/zip",
                "zip".getBytes()
        );
        List<PackageEntry> entries = List.of(
                new PackageEntry("SKILL.md", "name: demo".getBytes(), 10, "text/markdown")
        );
        when(zipPackageExtractor.extract(file)).thenReturn(entries);

        SkillVersion version = publishedVersionWithCompliance(23L, "1.2.0", "Article-17");
        when(skillPublishService.publishFromEntries(
                "global",
                entries,
                "user-1",
                SkillVisibility.PUBLIC,
                Set.of("SUPER_ADMIN"),
                false
        )).thenReturn(new SkillPublishService.PublishResult(8L, "demo-skill", version));

        PlatformPrincipal principal = new PlatformPrincipal(
                "user-1",
                "publisher",
                "publisher@example.com",
                "",
                "local",
                Set.of("SUPER_ADMIN")
        );

        service.publish(
                file,
                "global",
                false,
                principal,
                "127.0.0.1",
                "JUnit"
        );

        verify(auditLogService).record(
                eq("user-1"),
                eq("COMPAT_PUBLISH"),
                eq("SKILL_VERSION"),
                eq(23L),
                isNull(),
                eq("127.0.0.1"),
                eq("JUnit"),
                contains("\"snapshotKind\":\"latest_published_entered\"")
        );
        verify(auditLogService).record(
                eq("user-1"),
                eq("COMPAT_PUBLISH"),
                eq("SKILL_VERSION"),
                eq(23L),
                isNull(),
                eq("127.0.0.1"),
                eq("JUnit"),
                contains("\"controlId\":\"Article-17\"")
        );
    }

    private SkillVersion publishedVersionWithCompliance(Long versionId, String versionNumber, String controlId) {
        SkillVersion version = new SkillVersion(7L, versionNumber, "owner-1");
        version.setStatus(SkillVersionStatus.PUBLISHED);
        version.setParsedMetadataJson("""
                {
                  "frontmatter": {
                    "x-astron-compliance": [
                      {
                        "standard": "gdpr",
                        "standardVersion": "2024",
                        "controlId": "%s"
                      }
                    ]
                  }
                }
                """.formatted(controlId));
        ReflectionTestUtils.setField(version, "id", versionId);
        return version;
    }
}
