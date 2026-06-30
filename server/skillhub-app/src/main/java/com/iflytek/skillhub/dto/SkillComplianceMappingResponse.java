package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.domain.skill.metadata.ComplianceStandard;

public record SkillComplianceMappingResponse(
        ComplianceStandard standard,
        String standardVersion,
        String controlId,
        String controlTitle,
        String evidenceUrl
) {}
