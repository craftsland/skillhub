package com.iflytek.skillhub.domain.skill.metadata;

import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.events.CollectionStartEvent;
import org.yaml.snakeyaml.events.ScalarEvent;

import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parses `SKILL.md` frontmatter and body content into the normalized metadata model used by the
 * publish pipeline.
 */
public class SkillMetadataParser {

    private static final String FRONTMATTER_DELIMITER = "---";
    private static final int FRONTMATTER_CODE_POINT_LIMIT = 64 * 1024;
    private static final int FRONTMATTER_NESTING_DEPTH_LIMIT = 20;

    public SkillMetadata parse(String content) {
        if (content == null || content.isBlank()) {
            throw new DomainBadRequestException("error.skill.metadata.content.empty");
        }

        String trimmedContent = content.trim();

        if (!trimmedContent.startsWith(FRONTMATTER_DELIMITER)) {
            throw new DomainBadRequestException("error.skill.metadata.frontmatter.missingStart");
        }

        int firstDelimiterEnd = trimmedContent.indexOf('\n', FRONTMATTER_DELIMITER.length());
        if (firstDelimiterEnd == -1) {
            throw new DomainBadRequestException("error.skill.metadata.frontmatter.missingContent");
        }

        int secondDelimiterStart = trimmedContent.indexOf(FRONTMATTER_DELIMITER, firstDelimiterEnd + 1);
        if (secondDelimiterStart == -1) {
            throw new DomainBadRequestException("error.skill.metadata.frontmatter.missingEnd");
        }

        String yamlContent = trimmedContent.substring(firstDelimiterEnd + 1, secondDelimiterStart).trim();
        String body = trimmedContent.substring(secondDelimiterStart + FRONTMATTER_DELIMITER.length()).trim();

        Map<String, Object> frontmatter;
        try {
            frontmatter = parseFrontmatter(yamlContent);
        } catch (DomainBadRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new DomainBadRequestException("error.skill.metadata.yaml.invalid", e.getMessage());
        }

        String name = extractRequiredField(frontmatter, "name");
        String description = extractRequiredField(frontmatter, "description");
        String version = extractOptionalField(frontmatter, "version");
        if (version == null) {
            version = extractNestedOptionalField(frontmatter, "metadata", "version");
        }

        return new SkillMetadata(name, description, version, body, frontmatter);
    }

    private Map<String, Object> parseFrontmatter(String yamlContent) {
        validateFrontmatterCodePointLimit(yamlContent);
        try {
            Yaml yaml = newSafeYamlParser();
            rejectExplicitYamlTags(yaml, yamlContent);
            Object parsed = yaml.load(yamlContent);
            if (!(parsed instanceof Map)) {
                throw new DomainBadRequestException("error.skill.metadata.yaml.notMap");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) parsed;
            return map;
        } catch (DomainBadRequestException exception) {
            throw exception;
        } catch (Exception exception) {
            // Once strict parsing fails, tag syntax cannot be distinguished safely from prose
            // without reimplementing YAML. Valid bang-bearing prose is handled by the event path.
            if (yamlContent.contains("!")) {
                throw new DomainBadRequestException(
                        "error.skill.metadata.yaml.invalid",
                        "Explicit YAML tags are not allowed"
                );
            }
            if (isLoaderConstraintException(exception)) {
                throw new DomainBadRequestException("error.skill.metadata.yaml.invalid", exception.getMessage());
            }
            Map<String, Object> fallback = parseLooseFrontmatter(yamlContent);
            if (!fallback.isEmpty()) {
                return fallback;
            }
            throw exception;
        }
    }

    private Yaml newSafeYamlParser() {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setCodePointLimit(FRONTMATTER_CODE_POINT_LIMIT);
        options.setNestingDepthLimit(FRONTMATTER_NESTING_DEPTH_LIMIT);
        return new Yaml(new SafeConstructor(options));
    }

    private void rejectExplicitYamlTags(Yaml yaml, String yamlContent) {
        for (var event : yaml.parse(new StringReader(yamlContent))) {
            boolean taggedScalar = event instanceof ScalarEvent scalarEvent && scalarEvent.getTag() != null;
            boolean taggedCollection = event instanceof CollectionStartEvent collectionEvent
                    && collectionEvent.getTag() != null;
            if (taggedScalar || taggedCollection) {
                throw new DomainBadRequestException(
                        "error.skill.metadata.yaml.invalid",
                        "Explicit YAML tags are not allowed"
                );
            }
        }
    }

    private void validateFrontmatterCodePointLimit(String yamlContent) {
        if (yamlContent.codePointCount(0, yamlContent.length()) > FRONTMATTER_CODE_POINT_LIMIT) {
            throw new DomainBadRequestException(
                    "error.skill.metadata.yaml.invalid",
                    "Frontmatter exceeds the supported size"
            );
        }
    }

    private boolean isLoaderConstraintException(Exception exception) {
        String message = exception.getMessage();
        if (message == null) {
            return false;
        }
        return message.contains("exceeds the limit")
                || message.contains("Nesting Depth exceeded")
                || message.contains("found duplicate key");
    }

    private Map<String, Object> parseLooseFrontmatter(String yamlContent) {
        Map<String, Object> values = new LinkedHashMap<>();
        for (String rawLine : yamlContent.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            int separatorIndex = line.indexOf(':');
            if (separatorIndex <= 0) {
                continue;
            }

            String key = line.substring(0, separatorIndex).trim();
            String value = line.substring(separatorIndex + 1).trim();
            if (key.isEmpty()) {
                continue;
            }
            if (values.containsKey(key)) {
                throw new DomainBadRequestException(
                        "error.skill.metadata.yaml.invalid",
                        "Duplicate YAML keys are not allowed"
                );
            }

            values.put(key, stripWrappingQuotes(value));
        }
        return values;
    }

    private String stripWrappingQuotes(String value) {
        if (value.length() >= 2) {
            boolean wrappedInDoubleQuotes = value.startsWith("\"") && value.endsWith("\"");
            boolean wrappedInSingleQuotes = value.startsWith("'") && value.endsWith("'");
            if (wrappedInDoubleQuotes || wrappedInSingleQuotes) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }

    private String extractRequiredField(Map<String, Object> frontmatter, String fieldName) {
        Object value = frontmatter.get(fieldName);
        if (value == null) {
            throw new DomainBadRequestException("error.skill.metadata.requiredField.missing", fieldName);
        }
        return value.toString();
    }

    private String extractOptionalField(Map<String, Object> frontmatter, String fieldName) {
        Object value = frontmatter.get(fieldName);
        return value == null ? null : value.toString();
    }

    private String extractNestedOptionalField(Map<String, Object> frontmatter, String objectFieldName, String fieldName) {
        Object nestedValue = frontmatter.get(objectFieldName);
        if (!(nestedValue instanceof Map<?, ?> nestedMap)) {
            return null;
        }
        Object value = nestedMap.get(fieldName);
        return value == null ? null : value.toString();
    }
}
