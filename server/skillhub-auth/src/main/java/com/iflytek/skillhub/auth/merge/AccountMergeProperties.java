package com.iflytek.skillhub.auth.merge;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Release gate for the safe account-merge workflow.
 */
@Component
@ConfigurationProperties(prefix = "skillhub.auth.account-merge")
public class AccountMergeProperties {

    private boolean enabled;
    private boolean sessionCutoverComplete;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isSessionCutoverComplete() {
        return sessionCutoverComplete;
    }

    public void setSessionCutoverComplete(
            boolean sessionCutoverComplete) {
        this.sessionCutoverComplete = sessionCutoverComplete;
    }
}
