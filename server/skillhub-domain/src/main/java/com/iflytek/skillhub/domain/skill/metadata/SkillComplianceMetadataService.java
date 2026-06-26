package com.iflytek.skillhub.domain.skill.metadata;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Pattern;

/**
 * Validates and extracts version-scoped compliance mappings from parsed frontmatter metadata.
 */
public class SkillComplianceMetadataService {

    private static final String COMPLIANCE_FIELD = "x-astron-compliance";
    private static final int MAX_ITEMS = 20;
    private static final int MAX_STANDARD_VERSION_LENGTH = 32;
    private static final int MAX_CONTROL_TITLE_LENGTH = 200;
    private static final Pattern CONTROL_ID_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$");
    private static final Set<String> ALLOWED_KEYS = Set.of(
            "standard",
            "standardVersion",
            "controlId",
            "controlTitle",
            "evidenceUrl"
    );

    private final ObjectMapper objectMapper;

    public SkillComplianceMetadataService() {
        this(new ObjectMapper());
    }

    public SkillComplianceMetadataService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ParseResult parseFrontmatter(Map<String, Object> frontmatter) {
        if (frontmatter == null || frontmatter.isEmpty()) {
            return ParseResult.empty();
        }

        Object rawMappings = frontmatter.get(COMPLIANCE_FIELD);
        if (rawMappings == null) {
            return ParseResult.empty();
        }
        if (!(rawMappings instanceof List<?> items) || items.isEmpty()) {
            return ParseResult.invalid("x-astron-compliance must be a non-empty array");
        }

        List<String> errors = new ArrayList<>();
        if (items.size() > MAX_ITEMS) {
            errors.add("x-astron-compliance must contain at most " + MAX_ITEMS + " items");
        }

        List<SkillComplianceMapping> mappings = new ArrayList<>();
        Set<String> seenKeys = new HashSet<>();
        for (int index = 0; index < items.size(); index++) {
            Object rawItem = items.get(index);
            if (!(rawItem instanceof Map<?, ?> rawMap)) {
                errors.add("x-astron-compliance[" + index + "] must be an object");
                continue;
            }

            Map<String, Object> item = normalizeItem(rawMap, index, errors);
            if (item == null) {
                continue;
            }

            ComplianceStandard standard = parseStandard(item, index, errors);
            String standardVersion = parseRequiredString(item, index, "standardVersion", MAX_STANDARD_VERSION_LENGTH, errors);
            String controlId = parseRequiredControlId(item, index, errors);
            String controlTitle = parseOptionalString(item, index, "controlTitle", MAX_CONTROL_TITLE_LENGTH, errors);
            String evidenceUrl = parseOptionalAbsoluteUri(item, index, errors);

            if (standard == null || standardVersion == null || controlId == null) {
                continue;
            }

            String duplicateKey = normalizedDuplicateKey(standard, standardVersion, controlId);
            if (!seenKeys.add(duplicateKey)) {
                errors.add("x-astron-compliance contains duplicate mapping " + duplicateKey);
                continue;
            }

            mappings.add(new SkillComplianceMapping(
                    standard,
                    standardVersion.trim(),
                    controlId.trim(),
                    controlTitle,
                    evidenceUrl
            ));
        }

        if (!errors.isEmpty()) {
            return new ParseResult(List.of(), List.copyOf(errors));
        }
        return new ParseResult(List.copyOf(mappings), List.of());
    }

    public List<SkillComplianceMapping> readFromParsedMetadataJson(String parsedMetadataJson) {
        if (parsedMetadataJson == null || parsedMetadataJson.isBlank()) {
            return List.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(
                    parsedMetadataJson,
                    new TypeReference<Map<String, Object>>() {}
            );
            Object rawFrontmatter = parsed.get("frontmatter");
            if (!(rawFrontmatter instanceof Map<?, ?> rawMap)) {
                return List.of();
            }
            Map<String, Object> frontmatter = new LinkedHashMap<>();
            rawMap.forEach((key, value) -> {
                if (key instanceof String stringKey) {
                    frontmatter.put(stringKey, value);
                }
            });
            ParseResult result = parseFrontmatter(frontmatter);
            return result.errors().isEmpty() ? result.mappings() : List.of();
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private Map<String, Object> normalizeItem(Map<?, ?> rawMap, int index, List<String> errors) {
        Map<String, Object> item = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                errors.add("x-astron-compliance[" + index + "] contains a non-string field name");
                return null;
            }
            item.put(key, entry.getValue());
        }

        for (String key : item.keySet()) {
            if (!ALLOWED_KEYS.contains(key)) {
                errors.add("x-astron-compliance[" + index + "]." + key + " is not allowed");
            }
        }
        return item;
    }

    private ComplianceStandard parseStandard(Map<String, Object> item, int index, List<String> errors) {
        Object rawValue = item.get("standard");
        if (!(rawValue instanceof String value) || value.isBlank()) {
            errors.add("x-astron-compliance[" + index + "].standard is required");
            return null;
        }
        return ComplianceStandard.findByValue(value)
                .orElseGet(() -> {
                    errors.add(
                            "x-astron-compliance[" + index + "].standard must be one of "
                                    + List.of("mitre_attack", "nist_csf", "gdpr", "hipaa", "soc2")
                    );
                    return null;
                });
    }

    private String parseRequiredString(Map<String, Object> item,
                                       int index,
                                       String fieldName,
                                       int maxLength,
                                       List<String> errors) {
        Object rawValue = item.get(fieldName);
        if (!(rawValue instanceof String value) || value.isBlank()) {
            errors.add("x-astron-compliance[" + index + "]." + fieldName + " is required");
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.length() > maxLength) {
            errors.add("x-astron-compliance[" + index + "]." + fieldName + " must be at most " + maxLength + " characters");
            return null;
        }
        return trimmed;
    }

    private String parseRequiredControlId(Map<String, Object> item, int index, List<String> errors) {
        String controlId = parseRequiredString(item, index, "controlId", 128, errors);
        if (controlId == null) {
            return null;
        }
        if (!CONTROL_ID_PATTERN.matcher(controlId).matches()) {
            errors.add("x-astron-compliance[" + index + "].controlId has an invalid format");
            return null;
        }
        return controlId;
    }

    private String parseOptionalString(Map<String, Object> item,
                                       int index,
                                       String fieldName,
                                       int maxLength,
                                       List<String> errors) {
        Object rawValue = item.get(fieldName);
        if (rawValue == null) {
            return null;
        }
        if (!(rawValue instanceof String value) || value.isBlank()) {
            errors.add("x-astron-compliance[" + index + "]." + fieldName + " must be a non-empty string");
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.length() > maxLength) {
            errors.add("x-astron-compliance[" + index + "]." + fieldName + " must be at most " + maxLength + " characters");
            return null;
        }
        return trimmed;
    }

    private String parseOptionalAbsoluteUri(Map<String, Object> item, int index, List<String> errors) {
        Object rawValue = item.get("evidenceUrl");
        if (rawValue == null) {
            return null;
        }
        if (!(rawValue instanceof String value) || value.isBlank()) {
            errors.add("x-astron-compliance[" + index + "].evidenceUrl must be an absolute URI");
            return null;
        }
        try {
            URI uri = URI.create(value.trim());
            if (!uri.isAbsolute()) {
                errors.add("x-astron-compliance[" + index + "].evidenceUrl must be an absolute URI");
                return null;
            }
            return uri.toString();
        } catch (IllegalArgumentException ex) {
            errors.add("x-astron-compliance[" + index + "].evidenceUrl must be an absolute URI");
            return null;
        }
    }

    private String normalizedDuplicateKey(ComplianceStandard standard, String standardVersion, String controlId) {
        return standard.value()
                + "/"
                + standardVersion.trim().toLowerCase(Locale.ROOT)
                + "/"
                + controlId.trim().toUpperCase(Locale.ROOT);
    }

    public record ParseResult(
            List<SkillComplianceMapping> mappings,
            List<String> errors
    ) {
        public static ParseResult empty() {
            return new ParseResult(List.of(), List.of());
        }

        public static ParseResult invalid(String error) {
            return new ParseResult(List.of(), List.of(error));
        }
    }
}
