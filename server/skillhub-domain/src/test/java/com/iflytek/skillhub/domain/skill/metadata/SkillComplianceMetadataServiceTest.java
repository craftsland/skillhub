package com.iflytek.skillhub.domain.skill.metadata;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SkillComplianceMetadataServiceTest {

    private final SkillComplianceMetadataService service =
            new SkillComplianceMetadataService(new ObjectMapper());

    @Test
    void parseFrontmatter_acceptsKnownComplianceMappings() {
        Map<String, Object> frontmatter = Map.of(
                "x-astron-compliance",
                List.of(
                        Map.of(
                                "standard", "mitre_attack",
                                "standardVersion", "v14.1",
                                "controlId", "T1059",
                                "controlTitle", "Command and Scripting Interpreter",
                                "evidenceUrl", "https://example.com/evidence"
                        )
                )
        );

        SkillComplianceMetadataService.ParseResult result = service.parseFrontmatter(frontmatter);

        assertThat(result.errors()).isEmpty();
        assertThat(result.mappings()).singleElement()
                .extracting(
                        SkillComplianceMapping::standard,
                        SkillComplianceMapping::standardVersion,
                        SkillComplianceMapping::controlId,
                        SkillComplianceMapping::controlTitle,
                        SkillComplianceMapping::evidenceUrl
                )
                .containsExactly(
                        ComplianceStandard.MITRE_ATTACK,
                        "v14.1",
                        "T1059",
                        "Command and Scripting Interpreter",
                        "https://example.com/evidence"
                );
    }

    @Test
    void parseFrontmatter_rejectsDuplicateMappingsAfterNormalization() {
        Map<String, Object> frontmatter = Map.of(
                "x-astron-compliance",
                List.of(
                        Map.of(
                                "standard", "gdpr",
                                "standardVersion", "2024",
                                "controlId", "article-17"
                        ),
                        Map.of(
                                "standard", "gdpr",
                                "standardVersion", " 2024 ",
                                "controlId", "ARTICLE-17"
                        )
                )
        );

        SkillComplianceMetadataService.ParseResult result = service.parseFrontmatter(frontmatter);

        assertThat(result.mappings()).isEmpty();
        assertThat(result.errors()).contains("x-astron-compliance contains duplicate mapping gdpr/2024/ARTICLE-17");
    }

    @Test
    void parseFrontmatter_rejectsNonArrayComplianceField() {
        Map<String, Object> frontmatter = Map.of(
                "x-astron-compliance",
                "gdpr:Article-17"
        );

        SkillComplianceMetadataService.ParseResult result = service.parseFrontmatter(frontmatter);

        assertThat(result.mappings()).isEmpty();
        assertThat(result.errors()).contains("x-astron-compliance must be a non-empty array");
    }

    @Test
    void readFromParsedMetadataJson_extractsMappingsFromStoredSkillMetadata() {
        String parsedMetadataJson = """
                {
                  "name": "demo",
                  "description": "demo",
                  "version": "1.0.0",
                  "body": "Body",
                  "frontmatter": {
                    "x-astron-compliance": [
                      {
                        "standard": "soc2",
                        "standardVersion": "2017",
                        "controlId": "CC6.1"
                      }
                    ]
                  }
                }
                """;

        List<SkillComplianceMapping> mappings = service.readFromParsedMetadataJson(parsedMetadataJson);

        assertThat(mappings).singleElement()
                .extracting(
                        SkillComplianceMapping::standard,
                        SkillComplianceMapping::standardVersion,
                        SkillComplianceMapping::controlId
                )
                .containsExactly(ComplianceStandard.SOC2, "2017", "CC6.1");
    }
}
