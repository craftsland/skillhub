package com.iflytek.skillhub.auth.policy;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AccessPolicyTest {

    @Test
    void openPolicy_alwaysAllows() {
        var policy = new OpenAccessPolicy();
        assertThat(policy.evaluate(context(
                "github",
                "123",
                "user@any.com",
                EmailAssurance.UNVERIFIED)))
                .isEqualTo(AccessDecision.ALLOW);
    }

    @Test
    void emailDomainPolicy_allowsMatchingVerifiedDomain() {
        var policy = new EmailDomainAccessPolicy(Set.of("company.com"));
        assertThat(policy.evaluate(context(
                "github",
                "123",
                "user@company.com",
                EmailAssurance.VERIFIED)))
                .isEqualTo(AccessDecision.ALLOW);
    }

    @Test
    void emailDomainPolicy_allowsAuthoritativeEmail() {
        var policy = new EmailDomainAccessPolicy(Set.of("company.com"));
        assertThat(policy.evaluate(context(
                "github",
                "123",
                "user@company.com",
                EmailAssurance.AUTHORITATIVE)))
                .isEqualTo(AccessDecision.ALLOW);
    }

    @Test
    void emailDomainPolicy_deniesNonMatchingDomain() {
        var policy = new EmailDomainAccessPolicy(Set.of("company.com"));
        assertThat(policy.evaluate(context(
                "github",
                "123",
                "user@other.com",
                EmailAssurance.VERIFIED)))
                .isEqualTo(AccessDecision.DENY);
    }

    @Test
    void emailDomainPolicy_deniesMissingEmail() {
        var policy = new EmailDomainAccessPolicy(Set.of("company.com"));
        assertThat(policy.evaluate(new IdentityAccessContext(
                "github",
                "github_user_id",
                "123",
                Optional.empty(),
                EmailAssurance.UNVERIFIED,
                IdentityLoginContext.empty())))
                .isEqualTo(AccessDecision.DENY);
    }

    @Test
    void emailDomainPolicy_deniesUnverifiedEmailFromMatchingDomain() {
        var policy = new EmailDomainAccessPolicy(Set.of("company.com"));
        assertThat(policy.evaluate(context(
                "github",
                "123",
                "user@company.com",
                EmailAssurance.UNVERIFIED)))
                .isEqualTo(AccessDecision.DENY);
    }

    @Test
    void providerAllowlistPolicy_allowsMatchingProvider() {
        var policy = new ProviderAllowlistAccessPolicy(Set.of("github"));
        assertThat(policy.evaluate(context(
                "github",
                "123",
                "u@a.com",
                EmailAssurance.VERIFIED)))
                .isEqualTo(AccessDecision.ALLOW);
    }

    @Test
    void providerAllowlistPolicy_deniesNonMatchingProvider() {
        var policy = new ProviderAllowlistAccessPolicy(Set.of("github"));
        assertThat(policy.evaluate(context(
                "google",
                "123",
                "u@a.com",
                EmailAssurance.VERIFIED)))
                .isEqualTo(AccessDecision.DENY);
    }

    @Test
    void subjectWhitelistPolicy_allowsMatchingSubject() {
        var policy = new SubjectWhitelistAccessPolicy(
                Set.of("github:12345"));
        assertThat(policy.evaluate(context(
                "github",
                "12345",
                "u@a.com",
                EmailAssurance.VERIFIED)))
                .isEqualTo(AccessDecision.ALLOW);
    }

    @Test
    void subjectWhitelistPolicy_deniesNonMatchingSubject() {
        var policy = new SubjectWhitelistAccessPolicy(
                Set.of("github:12345"));
        assertThat(policy.evaluate(context(
                "github",
                "99999",
                "u@a.com",
                EmailAssurance.VERIFIED)))
                .isEqualTo(AccessDecision.DENY);
    }

    private static IdentityAccessContext context(
            String provider,
            String subject,
            String email,
            EmailAssurance assurance) {
        return new IdentityAccessContext(
                provider,
                provider + "_user_id",
                subject,
                Optional.of(email),
                assurance,
                IdentityLoginContext.empty());
    }
}
