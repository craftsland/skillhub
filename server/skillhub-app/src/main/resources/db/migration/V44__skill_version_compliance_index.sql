CREATE INDEX IF NOT EXISTS idx_skill_version_compliance_mappings
ON skill_version
USING GIN ((parsed_metadata_json -> 'frontmatter' -> 'x-astron-compliance'));
