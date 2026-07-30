package com.iflytek.skillhub.auth.identity;

import io.micrometer.core.instrument.MeterRegistry;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
class IdentityLoginMetrics {

    private final MeterRegistry meterRegistry;

    IdentityLoginMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    void recordOutcome(
            String providerCode,
            IdentityLoginOutcome outcome) {
        String result;
        if (outcome instanceof
                IdentityLoginOutcome.Authenticated authenticated) {
            result = authenticated.accountCreated()
                    ? "provisioned"
                    : "authenticated";
        } else if (outcome instanceof
                IdentityLoginOutcome.PendingApproval) {
            result = "pending";
        } else {
            result = "link_required";
        }
        counter(providerCode, result);
    }

    void recordFailure(
            String providerCode,
            IdentityFailureCode failureCode) {
        counter(
                providerCode,
                failureCode.name().toLowerCase(Locale.ROOT));
    }

    void recordSystemError(String providerCode) {
        counter(providerCode, "system_error");
    }

    private void counter(
            String providerCode,
            String result) {
        meterRegistry.counter(
                "skillhub.identity.login",
                "provider",
                providerCode,
                "result",
                result).increment();
    }
}
