package com.iflytek.skillhub.service;

import com.iflytek.skillhub.metrics.SkillHubMetrics;
import com.iflytek.skillhub.search.SearchRebuildService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

class LabelSearchSyncServiceTest {

    @Test
    void rebuildSkillsShouldSkipNullsAndDuplicatesWhileProcessingLargeLists() {
        SearchRebuildService rebuildService = mock(SearchRebuildService.class);
        SkillHubMetrics metrics = mock(SkillHubMetrics.class);
        LabelSearchSyncService service = new LabelSearchSyncService(rebuildService, metrics);
        List<Long> skillIds = new ArrayList<>();
        skillIds.add(null);
        for (long i = 1; i <= 120; i++) {
            skillIds.add(i);
        }
        skillIds.add(50L);
        skillIds.add(120L);

        service.rebuildSkills(skillIds);

        for (long i = 1; i <= 120; i++) {
            verify(rebuildService).rebuildBySkill(i);
        }
        verifyNoMoreInteractions(rebuildService);
        verifyNoInteractions(metrics);
    }

    @Test
    void rebuildSkillFailureShouldIncrementMetric() {
        SearchRebuildService rebuildService = mock(SearchRebuildService.class);
        doThrow(new IllegalStateException("search unavailable"))
                .when(rebuildService)
                .rebuildBySkill(42L);

        contextRunner(rebuildService).run(context -> {
            LabelSearchSyncService service = context.getBean(LabelSearchSyncService.class);
            SimpleMeterRegistry meterRegistry = context.getBean(SimpleMeterRegistry.class);

            service.rebuildSkill(42L);

            assertThat(meterRegistry.get("skillhub.search.rebuild.failure").counter().count())
                    .isEqualTo(1.0d);
        });
    }

    @Test
    void rebuildSkillsShouldCountEachFailureAndContinue() {
        SearchRebuildService rebuildService = mock(SearchRebuildService.class);
        doThrow(new IllegalStateException("search unavailable"))
                .when(rebuildService)
                .rebuildBySkill(2L);
        doThrow(new IllegalStateException("search unavailable"))
                .when(rebuildService)
                .rebuildBySkill(3L);

        contextRunner(rebuildService).run(context -> {
            LabelSearchSyncService service = context.getBean(LabelSearchSyncService.class);
            SimpleMeterRegistry meterRegistry = context.getBean(SimpleMeterRegistry.class);

            service.rebuildSkills(List.of(1L, 2L, 3L, 4L));

            assertThat(meterRegistry.get("skillhub.search.rebuild.failure").counter().count())
                    .isEqualTo(2.0d);
            verify(rebuildService).rebuildBySkill(1L);
            verify(rebuildService).rebuildBySkill(2L);
            verify(rebuildService).rebuildBySkill(3L);
            verify(rebuildService).rebuildBySkill(4L);
            verifyNoMoreInteractions(rebuildService);
        });
    }

    private ApplicationContextRunner contextRunner(SearchRebuildService rebuildService) {
        return new ApplicationContextRunner()
                .withBean(SearchRebuildService.class, () -> rebuildService)
                .withBean(SimpleMeterRegistry.class)
                .withBean(SkillHubMetrics.class)
                .withBean(LabelSearchSyncService.class);
    }
}
