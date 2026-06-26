package com.iflytek.skillhub.service;

import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.rbac.RbacService;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.namespace.NamespaceRepository;
import com.iflytek.skillhub.domain.review.ReviewService;
import com.iflytek.skillhub.domain.review.ReviewTask;
import com.iflytek.skillhub.domain.review.ReviewTaskRepository;
import com.iflytek.skillhub.domain.skill.SkillVersion;
import com.iflytek.skillhub.domain.skill.SkillVersionRepository;
import com.iflytek.skillhub.dto.ReviewTaskResponse;
import com.iflytek.skillhub.repository.GovernanceQueryRepository;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class ReviewPortalAppServiceTest {

    private final ReviewService reviewService = mock(ReviewService.class);
    private final ReviewTaskRepository reviewTaskRepository = mock(ReviewTaskRepository.class);
    private final NamespaceRepository namespaceRepository = mock(NamespaceRepository.class);
    private final GovernanceQueryRepository governanceQueryRepository = mock(GovernanceQueryRepository.class);
    private final RbacService rbacService = mock(RbacService.class);
    private final AuditLogService auditLogService = mock(AuditLogService.class);
    private final SkillVersionRepository skillVersionRepository = mock(SkillVersionRepository.class);

    private final ReviewPortalAppService service = new ReviewPortalAppService(
            reviewService,
            reviewTaskRepository,
            namespaceRepository,
            governanceQueryRepository,
            rbacService,
            auditLogService,
            skillVersionRepository
    );

    @Test
    void approveReview_recordsComplianceSnapshotInAuditDetail() {
        ReviewTask task = new ReviewTask(22L, 5L, "owner-1");
        ReflectionTestUtils.setField(task, "id", 9L);

        SkillVersion version = new SkillVersion(7L, "1.0.0", "owner-1");
        ReflectionTestUtils.setField(version, "id", 22L);
        version.setParsedMetadataJson("""
                {
                  "frontmatter": {
                    "x-astron-compliance": [
                      {
                        "standard": "gdpr",
                        "standardVersion": "2024",
                        "controlId": "Article-17"
                      }
                    ]
                  }
                }
                """);

        when(reviewService.approveReview(9L, "reviewer-1", "looks good", Map.of(), Set.of("SKILL_ADMIN")))
                .thenReturn(task);
        when(rbacService.getUserRoleCodes("reviewer-1")).thenReturn(Set.of("SKILL_ADMIN"));
        when(skillVersionRepository.findById(22L)).thenReturn(Optional.of(version));
        when(governanceQueryRepository.getReviewTaskResponse(task))
                .thenReturn(new ReviewTaskResponse(9L, 22L, "team", "demo", "1.0.0", "APPROVED", "owner-1", null, "reviewer-1", null, "looks good", null, null));

        service.approveReview(
                9L,
                "looks good",
                "reviewer-1",
                Map.of(),
                new AuditRequestContext("127.0.0.1", "JUnit")
        );

        verify(auditLogService).record(
                eq("reviewer-1"),
                eq("REVIEW_APPROVE"),
                eq("REVIEW_TASK"),
                eq(9L),
                isNull(),
                eq("127.0.0.1"),
                eq("JUnit"),
                contains("\"snapshotKind\":\"latest_published_entered\"")
        );
        verify(auditLogService).record(
                eq("reviewer-1"),
                eq("REVIEW_APPROVE"),
                eq("REVIEW_TASK"),
                eq(9L),
                isNull(),
                eq("127.0.0.1"),
                eq("JUnit"),
                contains("\"controlId\":\"Article-17\"")
        );
    }
}
