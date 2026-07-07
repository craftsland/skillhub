package com.iflytek.skillhub.domain.skill.metadata;

import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SkillMetadataParserTest {

    private final SkillMetadataParser parser = new SkillMetadataParser();

    @Test
    void testParseStandardFrontmatterAndBody() {
        String content = """
            ---
            name: test-skill
            description: A test skill
            version: 1.0.0
            ---
            # Test Skill

            This is the body content.
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("test-skill", metadata.name());
        assertEquals("A test skill", metadata.description());
        assertEquals("1.0.0", metadata.version());
        assertTrue(metadata.body().contains("# Test Skill"));
        assertTrue(metadata.body().contains("This is the body content."));
    }

    @Test
    void testExtensionFieldsPreservedInFrontmatter() {
        String content = """
            ---
            name: extended-skill
            description: Skill with extra fields
            version: 2.0.0
            author: John Doe
            tags:
              - ai
              - automation
            custom_field: custom_value
            ---
            Body content here.
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("extended-skill", metadata.name());
        assertEquals("Skill with extra fields", metadata.description());
        assertEquals("2.0.0", metadata.version());
        assertEquals("John Doe", metadata.frontmatter().get("author"));
        assertEquals("custom_value", metadata.frontmatter().get("custom_field"));
        assertNotNull(metadata.frontmatter().get("tags"));
    }

    @Test
    void testThrowsWhenNoFrontmatter() {
        String content = "# Just a markdown file without frontmatter";

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.frontmatter.missingStart", exception.messageCode());
    }

    @Test
    void testThrowsWhenMissingName() {
        String content = """
            ---
            description: Missing name field
            version: 1.0.0
            ---
            Body
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.requiredField.missing", exception.messageCode());
        assertEquals("name", exception.messageArgs()[0]);
    }

    @Test
    void testThrowsWhenMissingDescription() {
        String content = """
            ---
            name: test-skill
            version: 1.0.0
            ---
            Body
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.requiredField.missing", exception.messageCode());
        assertEquals("description", exception.messageArgs()[0]);
    }

    @Test
    void testAllowsMissingVersion() {
        String content = """
            ---
            name: test-skill
            description: Test description
            ---
            Body
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("test-skill", metadata.name());
        assertEquals("Test description", metadata.description());
        assertNull(metadata.version());
    }

    @Test
    void testUsesMetadataVersionWhenTopLevelVersionIsMissing() {
        String content = """
            ---
            name: agentguard
            description: Agent security guard
            metadata:
              author: GoPlusSecurity
              version: "1.1"
            ---
            Body
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("agentguard", metadata.name());
        assertEquals("Agent security guard", metadata.description());
        assertEquals("1.1", metadata.version());
    }

    @Test
    void testTopLevelVersionTakesPrecedenceOverMetadataVersion() {
        String content = """
            ---
            name: versioned-skill
            description: Prefer top-level version
            version: 2.0.0
            metadata:
              version: "1.1"
            ---
            Body
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("versioned-skill", metadata.name());
        assertEquals("Prefer top-level version", metadata.description());
        assertEquals("2.0.0", metadata.version());
    }

    @Test
    void testFallsBackToLooseFrontmatterParsingWhenYamlSyntaxIsNotStrict() {
        String content = """
            ---
            name: test-skill
            description: [unclosed bracket
            version: 1.0.0
            ---
            Body
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("test-skill", metadata.name());
        assertEquals("[unclosed bracket", metadata.description());
        assertEquals("1.0.0", metadata.version());
    }

    @Test
    void rejectsOversizedFrontmatterInsteadOfFallingBackToLooseParsing() {
        String longDescription = "x".repeat(70_000);
        String content = """
            ---
            name: oversized-skill
            description: [unclosed bracket %s
            version: 1.0.0
            ---
            Body
            """.formatted(longDescription);

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.yaml.invalid", exception.messageCode());
    }

    @Test
    void rejectsDuplicateKeysInsteadOfFallingBackToLooseParsing() {
        String content = """
            ---
            name: original-skill
            name: overwritten-skill
            description: Duplicate keys should not be accepted
            version: 1.0.0
            ---
            Body
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.yaml.invalid", exception.messageCode());
    }

    @Test
    void rejectsExcessiveNestingInsteadOfFallingBackToLooseParsing() {
        String nestedValue = "[".repeat(25) + "value" + "]".repeat(25);
        String content = """
            ---
            name: deeply-nested-skill
            description: Deeply nested frontmatter should not be accepted
            metadata: %s
            version: 1.0.0
            ---
            Body
            """.formatted(nestedValue);

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.yaml.invalid", exception.messageCode());
    }

    @Test
    void rejectsExplicitYamlTagsInsteadOfFallingBackToLooseParsing() {
        String content = """
            ---
            name: !!java.net.URL ["https://example.test"]
            description: malicious tag should not be accepted
            version: 1.0.0
            ---
            Body
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.yaml.invalid", exception.messageCode());
    }

    @Test
    void rejectsSingleBangYamlTagsInsteadOfFallingBackToLooseParsing() {
        String content = """
            ---
            name: !java.net.URL ["https://example.test"]
            description: malicious tag should not be accepted
            version: 1.0.0
            ---
            Body
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.yaml.invalid", exception.messageCode());
    }

    @Test
    void rejectsUriStyleYamlTagsInsteadOfFallingBackToLooseParsing() {
        String content = """
            ---
            name: !<tag:yaml.org,2002:java.net.URL> ["https://example.test"]
            description: malicious tag should not be accepted
            version: 1.0.0
            ---
            Body
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.yaml.invalid", exception.messageCode());
    }

    @Test
    void rejectsAnchoredExplicitYamlTagsInsteadOfFallingBackToLooseParsing() {
        String content = """
            ---
            name: &x !!java.net.URL ["https://example.test"]
            description: anchored malicious tag should not be accepted
            version: 1.0.0
            ---
            Body
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.yaml.invalid", exception.messageCode());
    }

    @Test
    void allowsPlainScalarExclamationMarks() {
        String content = """
            ---
            name: Excited Skill
            description: This is important!
            version: 1.0.0
            ---
            Body
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("This is important!", metadata.description());
    }

    @Test
    void allowsPlainScalarCommaBeforeExclamationWord() {
        String content = """
            ---
            name: css-guidance
            description: Avoid CSS, !important when possible
            version: 1.0.0
            ---
            Body
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("Avoid CSS, !important when possible", metadata.description());
    }

    @Test
    void testAllowsColonInDescriptionWithoutStrictYamlQuoting() {
        String content = """
            ---
            name: clawdbot
            description: Send messages from Clawdbot via the discord tool: send messages, react, post or edit
            version: 1.0.0
            ---
            Body
            """;

        SkillMetadata metadata = parser.parse(content);

        assertEquals("clawdbot", metadata.name());
        assertEquals("Send messages from Clawdbot via the discord tool: send messages, react, post or edit", metadata.description());
        assertEquals("1.0.0", metadata.version());
    }

    @Test
    void testThrowsWhenNoClosingDelimiter() {
        String content = """
            ---
            name: test-skill
            description: No closing delimiter
            version: 1.0.0
            """;

        DomainBadRequestException exception = assertThrows(
            DomainBadRequestException.class,
            () -> parser.parse(content)
        );
        assertEquals("error.skill.metadata.frontmatter.missingEnd", exception.messageCode());
    }
}
