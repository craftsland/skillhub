package com.iflytek.skillhub.auth.merge;

import java.util.UUID;

/**
 * Non-sensitive redirect metadata retained when a browser provider fails.
 */
public record AccountMergeBrowserFlowReference(
        AccountMergeBrowserPhase phase,
        UUID intentId
) {
}
