package com.iflytek.skillhub.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.observability.RequestIdAccessor;
import com.iflytek.skillhub.observability.RequestIdThreadLocalAccessor;
import io.micrometer.context.ContextRegistry;
import io.micrometer.context.ContextSnapshotFactory;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.support.ContextPropagatingTaskDecorator;
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
    void skillhubEventExecutor_propagatesAndClearsRequestIdContext() throws Exception {
        RequestIdAccessor requestIdAccessor = new RequestIdAccessor();
        ContextRegistry contextRegistry = new ContextRegistry()
                .registerThreadLocalAccessor(
                        new RequestIdThreadLocalAccessor(requestIdAccessor)
                );
        ContextSnapshotFactory snapshotFactory = ContextSnapshotFactory.builder()
                .contextRegistry(contextRegistry)
                .clearMissing(true)
                .build();
        ThreadPoolTaskExecutor executor =
                (ThreadPoolTaskExecutor) new AsyncConfig().skillhubEventExecutor(
                        new ContextPropagatingTaskDecorator(snapshotFactory)
                );
        try {
            CompletableFuture<String> propagatedRequestId = new CompletableFuture<>();
            try (RequestIdAccessor.Scope ignored = requestIdAccessor.open("req-597")) {
                executor.execute(
                        () -> propagatedRequestId.complete(requestIdAccessor.current())
                );
            }

            assertThat(propagatedRequestId.get(5, TimeUnit.SECONDS)).isEqualTo("req-597");

            CompletableFuture<String> nextRequestId = new CompletableFuture<>();
            executor.execute(() -> nextRequestId.complete(requestIdAccessor.current()));

            assertThat(nextRequestId.get(5, TimeUnit.SECONDS)).isNull();
        } finally {
            executor.shutdown();
        }
    }
}
