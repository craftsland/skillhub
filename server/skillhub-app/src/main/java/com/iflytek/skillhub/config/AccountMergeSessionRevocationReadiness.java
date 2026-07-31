package com.iflytek.skillhub.config;

import com.iflytek.skillhub.auth.merge.AccountMergeProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Component;

/**
 * Fails startup when safe account merge is enabled without an indexed Spring
 * Session repository capable of deleting every secondary-user session.
 */
@Component
@ConditionalOnProperty(
        prefix = "skillhub.auth.account-merge",
        name = "enabled",
        havingValue = "true")
public class AccountMergeSessionRevocationReadiness {

    public AccountMergeSessionRevocationReadiness(
            FindByIndexNameSessionRepository<?> sessionRepository,
            AccountMergeProperties properties) {
        if (!properties.isSessionCutoverComplete()) {
            throw new IllegalStateException(
                    "Safe account merge requires a completed "
                            + "Spring Session namespace cutover; set "
                            + "skillhub.auth.account-merge."
                            + "session-cutover-complete=true only "
                            + "after every legacy session has been "
                            + "invalidated");
        }
    }
}
