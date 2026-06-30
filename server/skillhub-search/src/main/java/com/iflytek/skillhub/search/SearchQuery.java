package com.iflytek.skillhub.search;

import com.iflytek.skillhub.domain.skill.metadata.ComplianceStandard;
import java.util.List;

/**
 * Immutable search request model shared between application code and search implementations.
 */
public record SearchQuery(
        String keyword,
        Long namespaceId,
        SearchVisibilityScope visibilityScope,
        String sortBy,
        int page,
        int size,
        List<String> labelSlugs,
        ComplianceStandard complianceStandard,
        boolean requireInstallableLatest
) {
    public SearchQuery(
            String keyword,
            Long namespaceId,
            SearchVisibilityScope visibilityScope,
            String sortBy,
            int page,
            int size,
            List<String> labelSlugs,
            boolean requireInstallableLatest) {
        this(keyword, namespaceId, visibilityScope, sortBy, page, size, labelSlugs, null, requireInstallableLatest);
    }

    public SearchQuery(
            String keyword,
            Long namespaceId,
            SearchVisibilityScope visibilityScope,
            String sortBy,
            int page,
            int size,
            List<String> labelSlugs) {
        this(keyword, namespaceId, visibilityScope, sortBy, page, size, labelSlugs, null, false);
    }

    public SearchQuery(
            String keyword,
            Long namespaceId,
            SearchVisibilityScope visibilityScope,
            String sortBy,
            int page,
            int size) {
        this(keyword, namespaceId, visibilityScope, sortBy, page, size, List.of(), null, false);
    }
}
