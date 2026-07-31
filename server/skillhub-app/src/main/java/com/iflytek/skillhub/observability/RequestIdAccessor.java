package com.iflytek.skillhub.observability;

import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * Holds the current SkillHub request identifier independently from the logging implementation.
 *
 * <p>The thread-local value is authoritative. MDC is maintained only as a mirror for log
 * correlation.</p>
 */
@Component
public class RequestIdAccessor {

    public static final String MDC_KEY = "requestId";

    private final ThreadLocal<String> currentRequestId = new ThreadLocal<>();

    /**
     * Returns the current request identifier, or {@code null} outside a request/task scope.
     */
    public String current() {
        return currentRequestId.get();
    }

    /**
     * Opens a nested request identifier scope on the current thread.
     */
    public Scope open(String requestId) {
        Objects.requireNonNull(requestId, "requestId must not be null");
        if (requestId.isBlank()) {
            throw new IllegalArgumentException("requestId must not be blank");
        }

        String previousRequestId = currentRequestId.get();
        replace(requestId);
        return new Scope(previousRequestId, requestId);
    }

    void replace(String requestId) {
        if (requestId == null) {
            currentRequestId.remove();
            MDC.remove(MDC_KEY);
            return;
        }
        currentRequestId.set(requestId);
        MDC.put(MDC_KEY, requestId);
    }

    /**
     * A same-thread, LIFO scope for the request identifier.
     */
    public final class Scope implements AutoCloseable {

        private final String previousRequestId;
        private final String installedRequestId;
        private boolean closed;

        private Scope(String previousRequestId, String installedRequestId) {
            this.previousRequestId = previousRequestId;
            this.installedRequestId = installedRequestId;
        }

        @Override
        public void close() {
            if (closed) {
                return;
            }
            if (!Objects.equals(currentRequestId.get(), installedRequestId)) {
                throw new IllegalStateException("Request ID scopes must close on the owning thread in LIFO order");
            }
            replace(previousRequestId);
            closed = true;
        }
    }
}
