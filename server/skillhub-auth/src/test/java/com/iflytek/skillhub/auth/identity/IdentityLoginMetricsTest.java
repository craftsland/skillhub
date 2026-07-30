package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.Set;
import org.junit.jupiter.api.Test;

class IdentityLoginMetricsTest {

    @Test
    void recordsBoundedOutcomeAndFailureTags() {
        SimpleMeterRegistry registry =
                new SimpleMeterRegistry();
        IdentityLoginMetrics metrics =
                new IdentityLoginMetrics(registry);
        PlatformPrincipal principal = new PlatformPrincipal(
                "usr_1",
                "alice",
                null,
                null,
                "github",
                Set.of("USER"));

        metrics.recordOutcome(
                "github",
                new IdentityLoginOutcome.Authenticated(
                        principal,
                        true,
                        true));
        metrics.recordOutcome(
                "github",
                new IdentityLoginOutcome.PendingApproval(
                        "ACCOUNT_PENDING"));
        metrics.recordOutcome(
                "github",
                new IdentityLoginOutcome.LinkRequired(
                        "EMAIL_COLLISION"));
        metrics.recordFailure(
                "github",
                IdentityFailureCode.ACCESS_DENIED);

        assertThat(counter(
                registry,
                "provisioned")).isEqualTo(1.0);
        assertThat(counter(
                registry,
                "pending")).isEqualTo(1.0);
        assertThat(counter(
                registry,
                "link_required")).isEqualTo(1.0);
        assertThat(counter(
                registry,
                "access_denied")).isEqualTo(1.0);
    }

    private static double counter(
            SimpleMeterRegistry registry,
            String result) {
        return registry.get("skillhub.identity.login")
                .tags(
                        "provider",
                        "github",
                        "result",
                        result)
                .counter()
                .count();
    }
}
