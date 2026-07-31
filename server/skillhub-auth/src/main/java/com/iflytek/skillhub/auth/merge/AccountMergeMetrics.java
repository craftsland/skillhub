package com.iflytek.skillhub.auth.merge;

import io.micrometer.core.instrument.MeterRegistry;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * Low-cardinality account-merge metrics.
 *
 * <p>User IDs, intent IDs, session IDs, and request IDs are deliberately
 * excluded from metric tags.
 */
@Component
public class AccountMergeMetrics {

    private final MeterRegistry meterRegistry;

    public AccountMergeMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    public void record(
            String event,
            String result) {
        meterRegistry.counter(
                "skillhub.account.merge",
                "event",
                normalized(event),
                "result",
                normalized(result)).increment();
    }

    public void recordProviderProof(
            String providerCode,
            String phase,
            String result) {
        meterRegistry.counter(
                "skillhub.account.merge.provider.proof",
                "provider",
                providerCode,
                "phase",
                normalized(phase),
                "result",
                normalized(result)).increment();
    }

    public void recordSessionRevocation(String result) {
        meterRegistry.counter(
                "skillhub.account.merge.session.revocation",
                "result",
                normalized(result)).increment();
    }

    private String normalized(String value) {
        if (value == null
                || value.isBlank()
                || value.length() > 64) {
            return "unknown";
        }
        return value.toLowerCase(Locale.ROOT);
    }
}
