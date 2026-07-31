package com.iflytek.skillhub.auth.cas;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.provider.BrowserAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.BrowserAuthenticationMethod;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.provider.ProviderInstanceDefinition;
import com.iflytek.skillhub.auth.provider.SubjectNormalization;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Maps one verified CAS exchange into provider facts consumed by the unified
 * identity core.
 */
@Component
public final class CasAuthenticationAdapter
        implements BrowserAuthenticationAdapter<CasAuthenticationExchange> {

    static final String DISPLAY_NAME_ATTRIBUTE = "cas_display_name";
    static final String EMAIL_ATTRIBUTE = "cas_email";
    static final String AVATAR_ATTRIBUTE = "cas_avatar_url";
    private static final int MAX_SUBJECT_LENGTH = 4096;

    private final CasProviderConfiguration configuration;

    CasAuthenticationAdapter(
            CasProviderConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public ProviderInstanceDefinition provider() {
        if (!configuration.enabled()) {
            return new ProviderInstanceDefinition(
                    "cas",
                    "cas",
                    "disabled",
                    "CAS",
                    "cas_principal",
                    "cas_principal",
                    Map.of(
                            "cas_principal",
                            SubjectNormalization.EXACT),
                    List.of(DISPLAY_NAME_ATTRIBUTE),
                    List.of(EMAIL_ATTRIBUTE),
                    List.of(AVATAR_ATTRIBUTE),
                    EmailAssurance.PROVIDER_ASSERTED,
                    false);
        }
        CasProviderConfiguration.ResolvedCasProvider resolved =
                configuration.requireResolved();
        return new ProviderInstanceDefinition(
                resolved.providerCode(),
                "cas",
                resolved.authority(),
                resolved.displayName(),
                resolved.subjectType(),
                resolved.subjectType(),
                Map.of(
                        resolved.subjectType(),
                        SubjectNormalization.EXACT),
                List.of(DISPLAY_NAME_ATTRIBUTE),
                List.of(EMAIL_ATTRIBUTE),
                List.of(AVATAR_ATTRIBUTE),
                EmailAssurance.PROVIDER_ASSERTED);
    }

    @Override
    public Class<CasAuthenticationExchange> exchangeType() {
        return CasAuthenticationExchange.class;
    }

    @Override
    public BrowserAuthenticationMethod loginMethod() {
        return BrowserAuthenticationMethod.CAS_REDIRECT;
    }

    @Override
    public ProviderAuthenticationResult authenticate(
            CasAuthenticationExchange exchange) {
        CasProviderConfiguration.ResolvedCasProvider resolved =
                configuration.requireResolved();
        String subject = resolved.subjectAttribute()
                .map(attribute -> requireUniqueSubject(
                        exchange.attributes().get(attribute)))
                .orElse(exchange.principal());

        Map<String, List<ProviderAttributeValue>> attributes =
                new LinkedHashMap<>();
        putMapped(
                attributes,
                DISPLAY_NAME_ATTRIBUTE,
                resolved.displayNameAttribute(),
                exchange.attributes(),
                ProviderAttributeTrust.ASSERTED);
        putMapped(
                attributes,
                EMAIL_ATTRIBUTE,
                resolved.emailAttribute(),
                exchange.attributes(),
                ProviderAttributeTrust.ASSERTED);
        putMapped(
                attributes,
                AVATAR_ATTRIBUTE,
                resolved.avatarAttribute(),
                exchange.attributes(),
                ProviderAttributeTrust.ASSERTED);

        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        resolved.subjectType(),
                        subject),
                List.of(),
                attributes,
                new ProtocolAuthenticationEvidence(
                        "cas",
                        exchange.authenticatedAt(),
                        Set.of("cas_service_ticket")));
    }

    private String requireUniqueSubject(List<String> values) {
        if (values == null || values.size() != 1
                || values.getFirst().isBlank()
                || values.getFirst().length()
                > MAX_SUBJECT_LENGTH) {
            throw new ProviderAuthenticationException(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_RESPONSE);
        }
        return values.getFirst();
    }

    private void putMapped(
            Map<String, List<ProviderAttributeValue>> target,
            String targetKey,
            Optional<String> sourceKey,
            Map<String, List<String>> source,
            ProviderAttributeTrust trust) {
        if (sourceKey.isEmpty()) {
            return;
        }
        List<String> values = source.get(sourceKey.orElseThrow());
        if (values == null) {
            return;
        }
        String first = values.stream()
                .filter(value -> !value.isBlank())
                .findFirst()
                .orElse(null);
        if (first != null) {
            target.put(
                    targetKey,
                    List.of(new ProviderAttributeValue(
                            first,
                            trust)));
        }
    }
}
