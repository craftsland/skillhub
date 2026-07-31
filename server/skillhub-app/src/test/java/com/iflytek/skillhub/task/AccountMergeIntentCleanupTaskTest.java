package com.iflytek.skillhub.task;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.merge.AccountMergeIntentService;
import org.junit.jupiter.api.Test;

class AccountMergeIntentCleanupTaskTest {

    @Test
    void expiresOneBoundedBatch() {
        AccountMergeIntentService intentService =
                mock(AccountMergeIntentService.class);
        when(intentService.expireDueIntents(
                AccountMergeIntentCleanupTask.BATCH_SIZE))
                .thenReturn(3);

        new AccountMergeIntentCleanupTask(
                intentService).expireDueIntents();

        verify(intentService).expireDueIntents(
                AccountMergeIntentCleanupTask.BATCH_SIZE);
    }
}
