package com.iflytek.skillhub.task;

import com.iflytek.skillhub.auth.merge.AccountMergeIntentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Marks expired account-merge intents terminal even when no later request
 * reads them.
 */
@Component
public class AccountMergeIntentCleanupTask {

    static final int BATCH_SIZE = 100;

    private static final Logger log = LoggerFactory.getLogger(
            AccountMergeIntentCleanupTask.class);

    private final AccountMergeIntentService intentService;

    public AccountMergeIntentCleanupTask(
            AccountMergeIntentService intentService) {
        this.intentService = intentService;
    }

    @Scheduled(
            fixedDelayString =
                    "${skillhub.auth.account-merge."
                            + "intent-cleanup-poll-interval-ms:60000}")
    public void expireDueIntents() {
        int expired = intentService.expireDueIntents(
                BATCH_SIZE);
        if (expired > 0) {
            log.info(
                    "Expired {} account merge intents",
                    expired);
        }
    }
}
