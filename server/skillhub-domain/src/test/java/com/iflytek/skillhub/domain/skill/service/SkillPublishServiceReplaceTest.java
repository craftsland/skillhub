package com.iflytek.skillhub.domain.skill.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.iflytek.skillhub.domain.namespace.NamespaceRepository;
import com.iflytek.skillhub.domain.review.ReviewTaskRepository;
import com.iflytek.skillhub.domain.review.ReviewTaskStatus;
import com.iflytek.skillhub.domain.security.SecurityScanService;
import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import com.iflytek.skillhub.domain.skill.Skill;
import com.iflytek.skillhub.domain.skill.SkillFileRepository;
import com.iflytek.skillhub.domain.skill.SkillRepository;
import com.iflytek.skillhub.domain.skill.SkillVersion;
import com.iflytek.skillhub.domain.skill.SkillVersionRepository;
import com.iflytek.skillhub.domain.skill.SkillVersionStatus;
import com.iflytek.skillhub.domain.skill.SkillVisibility;
import com.iflytek.skillhub.domain.skill.metadata.SkillMetadataParser;
import com.iflytek.skillhub.domain.skill.validation.PrePublishValidator;
import com.iflytek.skillhub.domain.skill.validation.SkillPackageValidator;
import com.iflytek.skillhub.storage.ObjectStorageService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for replacing a non-published version with the same version number.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SkillPublishServiceReplaceTest {

    @Mock
    private NamespaceRepository namespaceRepository;
    @Mock
    private NamespaceMemberRepository namespaceMemberRepository;
    @Mock
    private SkillRepository skillRepository;
    @Mock
    private SkillVersionRepository skillVersionRepository;
    @Mock
    private SkillFileRepository skillFileRepository;
    @Mock
    private ObjectStorageService objectStorageService;
    @Mock
    private SkillPackageValidator skillPackageValidator;
    @Mock
    private SkillMetadataParser skillMetadataParser;
    @Mock
    private PrePublishValidator prePublishValidator;
    @Mock
    private ReviewTaskRepository reviewTaskRepository;
    @Mock
    private SecurityScanService securityScanService;
    @Mock
    private SkillStorageDeletionCompensationService compensationService;
    @Mock
    private ApplicationEventPublisher eventPublisher;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private SkillPublishService newService() {
        return new SkillPublishService(
                namespaceRepository,
                namespaceMemberRepository,
                skillRepository,
                skillVersionRepository,
                skillFileRepository,
                objectStorageService,
                skillPackageValidator,
                skillMetadataParser,
                prePublishValidator,
                objectMapper,
                reviewTaskRepository,
                securityScanService,
                compensationService,
                eventPublisher,
                Clock.systemUTC());
    }

    private Skill skill(Long id, Long latestVersionId) {
        Skill skill = new Skill(1L, "demo", "owner", SkillVisibility.PUBLIC);
        ReflectionTestUtils.setField(skill, "id", id);
        skill.setLatestVersionId(latestVersionId);
        return skill;
    }

    private SkillVersion version(Long id, SkillVersionStatus status) {
        SkillVersion version = new SkillVersion(1L, "1.0.0", "owner");
        ReflectionTestUtils.setField(version, "id", id);
        version.setStatus(status);
        return version;
    }

    /**
     * A rejected version still owns a REJECTED review task. Deleting only the PENDING task
     * left that row referencing the skill_version, so the delete hit a foreign key
     * constraint and the re-upload surfaced as an HTTP 500.
     */
    @Test
    void replacingRejectedVersionRemovesReviewTasksOfEveryStatus() {
        Skill skill = skill(1L, 10L);
        SkillVersion rejected = version(10L, SkillVersionStatus.REJECTED);
        when(skillFileRepository.findByVersionId(10L)).thenReturn(List.of());

        SkillPublishService target = newService();
        ReflectionTestUtils.invokeMethod(
                target, "deleteReplaceableVersionArtifacts", skill, rejected, "ns");

        verify(reviewTaskRepository).deleteBySkillVersionIdIn(List.of(10L));
        verify(reviewTaskRepository, never())
                .findBySkillVersionIdAndStatus(any(), any(ReviewTaskStatus.class));
        verify(skillVersionRepository).delete(rejected);
    }

    @Test
    void replacingLatestVersionClearsTheLatestPointerFirst() {
        Skill skill = skill(1L, 10L);
        SkillVersion pending = version(10L, SkillVersionStatus.PENDING_REVIEW);
        when(skillFileRepository.findByVersionId(10L)).thenReturn(List.of());

        SkillPublishService target = newService();
        ReflectionTestUtils.invokeMethod(
                target, "deleteReplaceableVersionArtifacts", skill, pending, "ns");

        assertThat(skill.getLatestVersionId()).isNull();
        verify(skillRepository).save(skill);
        verify(reviewTaskRepository).deleteBySkillVersionIdIn(List.of(10L));
    }

    @Test
    void replacingPublishedVersionIsStillRejected() {
        Skill skill = skill(1L, 10L);
        SkillVersion published = version(10L, SkillVersionStatus.PUBLISHED);

        SkillPublishService target = newService();
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(
                target, "deleteReplaceableVersionArtifacts", skill, published, "ns"))
                .isInstanceOf(DomainBadRequestException.class);

        verify(reviewTaskRepository, never()).deleteBySkillVersionIdIn(any());
        verify(skillVersionRepository, never()).delete(any());
    }
}
