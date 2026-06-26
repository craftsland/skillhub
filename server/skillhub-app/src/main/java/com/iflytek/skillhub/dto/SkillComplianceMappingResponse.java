package com.iflytek.skillhub.dto;

public record SkillComplianceMappingResponse(
        String standard,
        String standardVersion,
        String controlId,
        String controlTitle,
        String evidenceUrl
) {}
