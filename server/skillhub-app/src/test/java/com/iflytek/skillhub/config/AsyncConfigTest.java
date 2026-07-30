package com.iflytek.skillhub.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

class AsyncConfigTest {

    @Test
    void asyncConfig_enablesAsyncAndScheduling() {
        assertThat(AsyncConfig.class).hasAnnotation(EnableAsync.class);
        assertThat(AsyncConfig.class).hasAnnotation(EnableScheduling.class);
    }

    @Test
    void skillhubEventExecutor_propagatesAndClearsMdc() throws Exception {
        ThreadPoolTaskExecutor executor =
                (ThreadPoolTaskExecutor) new AsyncConfig().skillhubEventExecutor();
        try {
            MDC.put("requestId", "req-597");
            CompletableFuture<String> propagatedRequestId = new CompletableFuture<>();
            executor.execute(() -> propagatedRequestId.complete(MDC.get("requestId")));
            MDC.clear();

            assertThat(propagatedRequestId.get(5, TimeUnit.SECONDS)).isEqualTo("req-597");

            CompletableFuture<String> nextRequestId = new CompletableFuture<>();
            executor.execute(() -> nextRequestId.complete(MDC.get("requestId")));

            assertThat(nextRequestId.get(5, TimeUnit.SECONDS)).isNull();
        } finally {
            MDC.clear();
            executor.shutdown();
        }
    }
}
