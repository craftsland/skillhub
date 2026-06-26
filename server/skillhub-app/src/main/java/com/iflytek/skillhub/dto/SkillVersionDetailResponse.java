package com.iflytek.skillhub.dto;

import java.time.Instant;
import java.util.List;

public record SkillVersionDetailResponse(
        Long id,
        String version,
        String status,
        String changelog,
        int fileCount,
        long totalSize,
        Instant publishedAt,
        String parsedMetadataJson,
        String manifestJson,
        List<SkillComplianceMappingResponse> complianceMappings
) {}
