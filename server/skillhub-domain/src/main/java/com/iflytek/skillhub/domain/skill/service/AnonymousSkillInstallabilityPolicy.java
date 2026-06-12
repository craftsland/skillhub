package com.iflytek.skillhub.domain.skill.service;

import com.iflytek.skillhub.domain.namespace.Namespace;
import com.iflytek.skillhub.domain.namespace.NamespaceStatus;
import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import com.iflytek.skillhub.domain.shared.exception.DomainForbiddenException;
import com.iflytek.skillhub.domain.skill.Skill;
import com.iflytek.skillhub.domain.skill.SkillStatus;
import com.iflytek.skillhub.domain.skill.SkillVersion;
import com.iflytek.skillhub.domain.skill.SkillVersionStatus;
import com.iflytek.skillhub.domain.skill.SkillVisibility;
import org.springframework.stereotype.Service;

/**
 * Defines the public install target contract for anonymous CLI consumers.
 */
@Service
public class AnonymousSkillInstallabilityPolicy {

    public boolean isAnonymousInstallable(Namespace namespace, Skill skill, SkillVersion version) {
        return isActiveNamespace(namespace)
                && isPublicActiveSkill(skill)
                && isInstallableVersion(version);
    }

    public boolean isInstallableVersion(SkillVersion version) {
        return version != null
                && version.getStatus() == SkillVersionStatus.PUBLISHED
                && version.isDownloadReady()
                && version.getYankedAt() == null;
    }

    public void assertAnonymousInstallable(Namespace namespace, Skill skill, SkillVersion version) {
        if (!isActiveNamespace(namespace)) {
            throw new DomainForbiddenException("error.namespace.archived", namespace == null ? null : namespace.getSlug());
        }
        if (!isPublicActiveSkill(skill)) {
            throw new DomainForbiddenException("error.skill.access.denied", skill == null ? null : skill.getSlug());
        }
        if (version == null) {
            throw new DomainBadRequestException("error.skill.version.latest.unavailable", skill.getSlug());
        }
        if (!isInstallableVersion(version)) {
            throw new DomainBadRequestException("error.skill.version.notDownloadable", version.getVersion());
        }
    }

    private boolean isActiveNamespace(Namespace namespace) {
        return namespace != null && namespace.getStatus() == NamespaceStatus.ACTIVE;
    }

    private boolean isPublicActiveSkill(Skill skill) {
        return skill != null
                && skill.getStatus() == SkillStatus.ACTIVE
                && !skill.isHidden()
                && skill.getVisibility() == SkillVisibility.PUBLIC;
    }
}
