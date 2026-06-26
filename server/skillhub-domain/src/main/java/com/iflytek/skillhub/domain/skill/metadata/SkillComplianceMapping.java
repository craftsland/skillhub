package com.iflytek.skillhub.domain.skill.metadata;

/**
 * Normalized phase-1 compliance mapping payload stored in parsed metadata and projected to APIs.
 */
public record SkillComplianceMapping(
        ComplianceStandard standard,
        String standardVersion,
        String controlId,
        String controlTitle,
        String evidenceUrl
) {}
