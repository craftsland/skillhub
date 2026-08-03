package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * Low-cardinality protocol metrics for LDAP authentication attempts.
 */
@Component
final class LdapAuthenticationMetrics {

    private final MeterRegistry meterRegistry;

    LdapAuthenticationMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    void recordSuccess(
            String providerCode,
            LdapTransport transport) {
        record(providerCode, transport, "success");
    }

    void recordFailure(
            String providerCode,
            LdapTransport transport,
            ProviderAuthenticationFailureCode failureCode) {
        record(
                providerCode,
                transport,
                failureCode.name().toLowerCase(Locale.ROOT));
    }

    private void record(
            String providerCode,
            LdapTransport transport,
            String result) {
        if (meterRegistry == null) {
            return;
        }
        meterRegistry.counter(
                "skillhub.auth.ldap",
                "provider",
                providerCode,
                "transport",
                transport.name().toLowerCase(Locale.ROOT),
                "result",
                result).increment();
    }

    static LdapAuthenticationMetrics noop() {
        return new LdapAuthenticationMetrics(null);
    }
}
