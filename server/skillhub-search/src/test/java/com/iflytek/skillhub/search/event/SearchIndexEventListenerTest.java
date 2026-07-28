package com.iflytek.skillhub.search.event;

import com.iflytek.skillhub.domain.event.SkillPublishedEvent;
import com.iflytek.skillhub.domain.event.SkillStatusChangedEvent;
import com.iflytek.skillhub.domain.event.SkillVersionYankedEvent;
import com.iflytek.skillhub.domain.skill.SkillStatus;
import com.iflytek.skillhub.search.SearchIndexService;
import com.iflytek.skillhub.search.SearchRebuildService;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class SearchIndexEventListenerTest {

    @Test
    void skillPublishedEventShouldTriggerSkillRebuild() {
        SearchRebuildService searchRebuildService = mock(SearchRebuildService.class);
        SearchIndexService searchIndexService = mock(SearchIndexService.class);
        SearchIndexEventListener listener = new SearchIndexEventListener(searchRebuildService, searchIndexService);

        listener.onSkillPublished(new SkillPublishedEvent(42L, 100L, "reviewer-1"));

        verify(searchRebuildService).rebuildBySkill(42L);
    }

    @Test
    void archivedStatusShouldRemoveSearchDocument() {
        SearchRebuildService searchRebuildService = mock(SearchRebuildService.class);
        SearchIndexService searchIndexService = mock(SearchIndexService.class);
        SearchIndexEventListener listener = new SearchIndexEventListener(searchRebuildService, searchIndexService);

        listener.onSkillStatusChanged(new SkillStatusChangedEvent(42L, SkillStatus.ACTIVE, SkillStatus.ARCHIVED));

        verify(searchIndexService).remove(42L);
    }

    @Test
    void yankedVersionShouldTriggerSkillRebuild() throws Exception {
        SearchRebuildService searchRebuildService = mock(SearchRebuildService.class);
        SearchIndexService searchIndexService = mock(SearchIndexService.class);
        SearchIndexEventListener listener = new SearchIndexEventListener(searchRebuildService, searchIndexService);

        Method handler = Arrays.stream(SearchIndexEventListener.class.getDeclaredMethods())
                .filter(method -> Arrays.equals(method.getParameterTypes(), new Class<?>[]{SkillVersionYankedEvent.class}))
                .findFirst()
                .orElse(null);

        assertThat(handler).isNotNull();
        handler.invoke(listener, new SkillVersionYankedEvent(42L, 100L, "admin-1"));
        verify(searchRebuildService).rebuildBySkill(42L);
    }
}
