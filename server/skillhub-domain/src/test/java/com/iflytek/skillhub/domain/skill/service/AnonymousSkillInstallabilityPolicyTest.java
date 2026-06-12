package com.iflytek.skillhub.domain.skill.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iflytek.skillhub.domain.namespace.Namespace;
import com.iflytek.skillhub.domain.namespace.NamespaceStatus;
import com.iflytek.skillhub.domain.skill.Skill;
import com.iflytek.skillhub.domain.skill.SkillStatus;
import com.iflytek.skillhub.domain.skill.SkillVersion;
import com.iflytek.skillhub.domain.skill.SkillVersionStatus;
import com.iflytek.skillhub.domain.skill.SkillVisibility;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class AnonymousSkillInstallabilityPolicyTest {

    private final AnonymousSkillInstallabilityPolicy policy = new AnonymousSkillInstallabilityPolicy();

    @Test
    void isAnonymousInstallable_returnsTrueForActivePublicSkillWithReadyPublishedVersion() {
        assertTrue(policy.isAnonymousInstallable(activeNamespace(), publicSkill(), readyPublishedVersion()));
    }

    @Test
    void isAnonymousInstallable_returnsFalseWhenNamespaceIsArchived() {
        Namespace namespace = activeNamespace();
        namespace.setStatus(NamespaceStatus.ARCHIVED);

        assertFalse(policy.isAnonymousInstallable(namespace, publicSkill(), readyPublishedVersion()));
    }

    @Test
    void isAnonymousInstallable_returnsFalseWhenSkillIsNotPublicActiveAndVisible() {
        Skill hidden = publicSkill();
        hidden.setHidden(true);
        assertFalse(policy.isAnonymousInstallable(activeNamespace(), hidden, readyPublishedVersion()));

        Skill archived = publicSkill();
        archived.setStatus(SkillStatus.ARCHIVED);
        assertFalse(policy.isAnonymousInstallable(activeNamespace(), archived, readyPublishedVersion()));

        assertFalse(policy.isAnonymousInstallable(
                activeNamespace(),
                new Skill(1L, "demo", "owner-1", SkillVisibility.NAMESPACE_ONLY),
                readyPublishedVersion()));
        assertFalse(policy.isAnonymousInstallable(
                activeNamespace(),
                new Skill(1L, "demo", "owner-1", SkillVisibility.PRIVATE),
                readyPublishedVersion()));
    }

    @Test
    void isAnonymousInstallable_returnsFalseWhenVersionIsNotPublishedReadyAndNotYanked() {
        assertFalse(policy.isAnonymousInstallable(activeNamespace(), publicSkill(), null));

        SkillVersion draft = readyPublishedVersion();
        draft.setStatus(SkillVersionStatus.DRAFT);
        assertFalse(policy.isAnonymousInstallable(activeNamespace(), publicSkill(), draft));

        SkillVersion notReady = readyPublishedVersion();
        notReady.setDownloadReady(false);
        assertFalse(policy.isAnonymousInstallable(activeNamespace(), publicSkill(), notReady));

        SkillVersion yankedStatus = readyPublishedVersion();
        yankedStatus.setStatus(SkillVersionStatus.YANKED);
        assertFalse(policy.isAnonymousInstallable(activeNamespace(), publicSkill(), yankedStatus));

        SkillVersion yankedMarker = readyPublishedVersion();
        yankedMarker.setYankedAt(Instant.parse("2026-03-01T10:00:00Z"));
        assertFalse(policy.isAnonymousInstallable(activeNamespace(), publicSkill(), yankedMarker));
    }

    private Namespace activeNamespace() {
        return new Namespace("global", "Global", "system");
    }

    private Skill publicSkill() {
        return new Skill(1L, "demo", "owner-1", SkillVisibility.PUBLIC);
    }

    private SkillVersion readyPublishedVersion() {
        SkillVersion version = new SkillVersion(1L, "1.0.0", "owner-1");
        version.setStatus(SkillVersionStatus.PUBLISHED);
        version.setDownloadReady(true);
        return version;
    }
}
