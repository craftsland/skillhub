package com.iflytek.skillhub.domain.skill.metadata;

import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;

import java.util.regex.Pattern;

/**
 * Validates version strings before they are persisted or embedded into shell-facing install
 * commands.
 */
public final class SkillVersionFormatValidator {

    private static final Pattern SAFE_VERSION_PATTERN =
            Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?");

    private SkillVersionFormatValidator() {
    }

    public static String validateOrNull(String version) {
        if (version == null) {
            return null;
        }
        requireSafe(version);
        return version;
    }

    public static void requireSafe(String version) {
        if (version == null || version.isBlank() || !SAFE_VERSION_PATTERN.matcher(version).matches()) {
            throw new DomainBadRequestException("error.skill.metadata.version.invalid", version);
        }
    }
}
