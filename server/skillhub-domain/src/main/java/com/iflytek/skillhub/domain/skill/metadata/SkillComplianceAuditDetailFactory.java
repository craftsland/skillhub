package com.iflytek.skillhub.domain.skill.metadata;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.domain.skill.SkillVersion;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds audit detail payloads that carry version-scoped compliance snapshots.
 */
public class SkillComplianceAuditDetailFactory {

    private final ObjectMapper objectMapper;
    private final SkillComplianceMetadataService complianceMetadataService;

    public SkillComplianceAuditDetailFactory() {
        this(new ObjectMapper(), new SkillComplianceMetadataService());
    }

    SkillComplianceAuditDetailFactory(ObjectMapper objectMapper,
                                      SkillComplianceMetadataService complianceMetadataService) {
        this.objectMapper = objectMapper;
        this.complianceMetadataService = complianceMetadataService;
    }

    public String latestPublishedEntered(SkillVersion version) {
        return latestPublishedEntered(version, Map.of());
    }

    public String latestPublishedEntered(SkillVersion version, Map<String, Object> extras) {
        return build("latest_published_entered", version, extras);
    }

    public String latestPublishedRemoved(SkillVersion version, Map<String, Object> extras) {
        return build("latest_published_removed", version, extras);
    }

    public String build(String snapshotKind, SkillVersion version, Map<String, Object> extras) {
        LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
        payload.put("snapshotKind", snapshotKind);
        payload.put("versionId", version.getId());
        payload.put("version", version.getVersion());
        payload.put(
                "compliance",
                complianceMetadataService.readFromParsedMetadataJson(version.getParsedMetadataJson())
        );
        if (extras != null && !extras.isEmpty()) {
            payload.putAll(extras);
        }
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize compliance audit detail", ex);
        }
    }
}
