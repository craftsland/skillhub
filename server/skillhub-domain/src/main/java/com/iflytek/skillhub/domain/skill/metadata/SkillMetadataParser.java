package com.iflytek.skillhub.domain.skill.metadata;

import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

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
        if (containsExplicitYamlTag(yamlContent)) {
            throw new DomainBadRequestException("error.skill.metadata.yaml.invalid", "Explicit YAML tags are not allowed");
        }
        try {
            Yaml yaml = newSafeYamlParser();
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

    private boolean containsExplicitYamlTag(String yamlContent) {
        return yamlContent.lines()
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .anyMatch(this::containsExplicitYamlTagInLine);
    }

    private boolean containsExplicitYamlTagInLine(String line) {
        String candidate = stripLeadingIndicatorsAndAnchors(line);
        if (startsWithExplicitYamlTag(candidate)) {
            return true;
        }
        if (candidate.startsWith("[") || candidate.startsWith("{")) {
            return containsFlowExplicitYamlTag(candidate);
        }

        int separatorIndex = line.indexOf(':');
        if (separatorIndex <= 0) {
            return false;
        }

        String value = stripLeadingAnchors(line.substring(separatorIndex + 1));
        if (startsWithExplicitYamlTag(value)) {
            return true;
        }
        return (value.startsWith("[") || value.startsWith("{")) && containsFlowExplicitYamlTag(value);
    }

    private String stripLeadingIndicatorsAndAnchors(String line) {
        String candidate = line.trim();
        boolean advanced;
        do {
            advanced = false;
            if (candidate.startsWith("- ") || candidate.startsWith("? ") || candidate.startsWith(": ")) {
                candidate = candidate.substring(1).trim();
                advanced = true;
                continue;
            }

            String withoutAnchor = stripLeadingAnchors(candidate);
            if (!withoutAnchor.equals(candidate)) {
                candidate = withoutAnchor;
                advanced = true;
            }
        } while (advanced);
        return candidate;
    }

    private String stripLeadingAnchors(String value) {
        String candidate = value.trim();
        while (candidate.startsWith("&") && candidate.length() > 1) {
            int end = 1;
            while (end < candidate.length()
                    && !Character.isWhitespace(candidate.charAt(end))
                    && !isYamlFlowDelimiter(candidate.charAt(end))) {
                end++;
            }
            if (end == 1) {
                break;
            }
            candidate = candidate.substring(end).trim();
        }
        return candidate;
    }

    private boolean startsWithExplicitYamlTag(String value) {
        return value.startsWith("!") && value.length() > 1 && !Character.isWhitespace(value.charAt(1));
    }

    private boolean containsFlowExplicitYamlTag(String value) {
        int flowDepth = 0;
        char quote = '\0';
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (quote != '\0') {
                if (current == quote && !isEscapedDoubleQuote(value, i, quote)) {
                    quote = '\0';
                }
                continue;
            }
            if (current == '\'' || current == '"') {
                quote = current;
                continue;
            }

            if (current == '[' || current == '{') {
                flowDepth++;
                if (startsWithExplicitYamlTag(stripLeadingAnchors(value.substring(i + 1)))) {
                    return true;
                }
                continue;
            }
            if (current == ']' || current == '}') {
                flowDepth = Math.max(0, flowDepth - 1);
                continue;
            }
            if (flowDepth > 0
                    && (current == ',' || current == ':')
                    && startsWithExplicitYamlTag(stripLeadingAnchors(value.substring(i + 1)))) {
                return true;
            }
        }
        return false;
    }

    private boolean isEscapedDoubleQuote(String value, int index, char quote) {
        if (quote != '"' || index == 0) {
            return false;
        }
        int backslashCount = 0;
        for (int i = index - 1; i >= 0 && value.charAt(i) == '\\'; i--) {
            backslashCount++;
        }
        return backslashCount % 2 == 1;
    }

    private boolean isYamlFlowDelimiter(char current) {
        return current == '[' || current == ']' || current == '{' || current == '}' || current == ',';
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
